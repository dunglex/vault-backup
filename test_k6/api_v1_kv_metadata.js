import http from 'k6/http';
import { check } from 'k6';
import { vaultToken, vaultURL } from './config.js';

const metadataURL = `${vaultURL}/v1/kv/metadata`;
const secretPath = 'infrastructure/kubernetes/000081';
const secretDataURL = `${vaultURL}/v1/kv/data/${secretPath}`;
const secretMetadataURL = `${metadataURL}/${secretPath}`;
const nestedMetadataURL = `${metadataURL}/infrastructure`;
const capture503Diagnostics = __ENV.CAPTURE_503_DIAGNOSTICS === 'true';

function log503Diagnostic(response) {
  if (!capture503Diagnostics || response.status !== 503) {
    return;
  }

  let reason = 'unrecognized response (body redacted)';
  try {
    const error = response.json('error');
    if (error === 'request timed out' || error === 'server is under maintenance') {
      reason = error;
    }
  } catch {
    reason = 'non-JSON response (body redacted)';
  }
  console.error(`503 diagnostic: route=authenticated_kv_metadata reason=${JSON.stringify(reason)}`);
}

export const options = {
  discardResponseBodies: true,
  scenarios: {
    auth_checks: {
      executor: 'shared-iterations',
      exec: 'authChecks',
      vus: 1,
      iterations: 1,
      startTime: '0s',
    },
    api_load: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RATE || 1000),
      timeUnit: '1s',
      duration: __ENV.DURATION || '30s',
      preAllocatedVUs: Number(__ENV.PREALLOCATED_VUS || 100),
      maxVUs: Number(__ENV.MAX_VUS || 200),
      startTime: '1s',
    },
  },
  thresholds: {
    checks: ['rate>0.99'],
    dropped_iterations: ['count==0'],
    http_req_failed: ['rate<0.01'],
  },
};

export function authChecks() {
  const unauthenticated = http.get(metadataURL, {
    responseCallback: http.expectedStatuses(401),
    tags: { name: 'unauthenticated' },
  });
  check(unauthenticated, {
    'API rejects requests without a managed token': (response) => response.status === 401,
  });

  const vaultTokenResponse = http.get(metadataURL, {
    headers: { 'X-Vault-Token': vaultToken },
    responseCallback: http.expectedStatuses(200),
    tags: { name: 'x_vault_token' },
  });
  check(vaultTokenResponse, {
    'API accepts X-Vault-Token': (response) => response.status === 200,
  });

  const bearerResponse = http.get(metadataURL, {
    headers: { Authorization: `Bearer ${vaultToken}` },
    responseCallback: http.expectedStatuses(200),
    tags: { name: 'bearer_token' },
  });
  check(bearerResponse, {
    'API accepts Bearer token': (response) => response.status === 200,
  });

  const secretResponse = http.get(secretDataURL, {
    headers: { 'X-Vault-Token': vaultToken },
    responseCallback: http.expectedStatuses(200),
    tags: { name: 'read_secret' },
  });
  check(secretResponse, {
    'API reads current KV data': (response) => response.status === 200,
  });

  const secretMetadataResponse = http.get(secretMetadataURL, {
    headers: { 'X-Vault-Token': vaultToken },
    responseCallback: http.expectedStatuses(200),
    tags: { name: 'read_secret_metadata' },
  });
  check(secretMetadataResponse, {
    'API reads metadata for a secret': (response) => response.status === 200,
  });

  const nestedMetadataResponse = http.request('LIST', nestedMetadataURL, null, {
    headers: { 'X-Vault-Token': vaultToken },
    responseCallback: http.expectedStatuses(200),
    tags: { name: 'list_nested_metadata' },
  });
  check(nestedMetadataResponse, {
    'API lists nested metadata keys': (response) => response.status === 200,
  });
}

export default function () {
  const response = http.get(metadataURL, {
    headers: { 'X-Vault-Token': vaultToken },
    responseType: capture503Diagnostics ? 'text' : 'none',
    responseCallback: http.expectedStatuses(200),
    tags: { name: 'authenticated_kv_metadata' },
  });
  log503Diagnostic(response);
  check(response, {
    'authenticated KV metadata responds with HTTP 200': (result) => result.status === 200,
  });
}
