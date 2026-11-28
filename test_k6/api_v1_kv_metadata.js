import http from 'k6/http';
import { check } from 'k6';
import { vaultToken, vaultURL } from './config.js';

const metadataURL = `${vaultURL}/v1/kv/metadata`;

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
}

export default function () {
  const response = http.get(metadataURL, {
    headers: { 'X-Vault-Token': vaultToken },
    responseCallback: http.expectedStatuses(200),
    tags: { name: 'authenticated_kv_metadata' },
  });
  check(response, {
    'authenticated KV metadata responds with HTTP 200': (result) => result.status === 200,
  });
}
