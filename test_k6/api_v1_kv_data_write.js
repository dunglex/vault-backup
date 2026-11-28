import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { vaultToken, vaultURL } from './config.js';

const rate = Number(__ENV.RATE || 10);
const duration = __ENV.DURATION || '10s';
const preAllocatedVUs = Number(__ENV.PREALLOCATED_VUS || 10);
const maxVUs = Number(__ENV.MAX_VUS || 50);
const payloadBytes = Number(__ENV.PAYLOAD_BYTES || 256);
const writePathPrefix = __ENV.WRITE_PATH_PREFIX || 'k6-performance';
const secretWriteDuration = new Trend('secret_write_duration', true);

if (!Number.isInteger(payloadBytes) || payloadBytes < 1 || payloadBytes > 65536) {
  throw new Error('PAYLOAD_BYTES must be an integer from 1 to 65536');
}
if (!writePathPrefix.split('/').every((segment) => (
  segment.length > 0 &&
  segment.length <= 127 &&
  /^[A-Za-z0-9-]+$/.test(segment)
))) {
  throw new Error('WRITE_PATH_PREFIX must contain slash-separated letters, digits, or hyphens');
}

const payload = 'x'.repeat(payloadBytes);

export const options = {
  discardResponseBodies: true,
  scenarios: {
    api_write_load: {
      executor: 'constant-arrival-rate',
      exec: 'writeSecret',
      rate,
      timeUnit: '1s',
      duration,
      preAllocatedVUs,
      maxVUs,
    },
  },
  thresholds: {
    checks: ['rate>0.99'],
    dropped_iterations: ['count==0'],
    'http_req_failed{operation:write_secret}': ['rate<0.01'],
  },
};

function testSecretURL(runPrefix, vu) {
  return `${vaultURL}/v1/kv/data/${runPrefix}/vu-${vu}`;
}

export function setup() {
  const response = http.get(`${vaultURL}/v1/kv/metadata`, {
    headers: { 'X-Vault-Token': vaultToken },
    responseCallback: http.expectedStatuses(200),
    tags: { operation: 'preflight' },
  });
  if (response.status !== 200) {
    throw new Error(`API preflight failed with HTTP ${response.status}`);
  }

  const runID = `${Date.now().toString(36)}-${Math.floor(Math.random() * 1e9).toString(36)}`;
  return { runPrefix: `${writePathPrefix}/${runID}` };
}

export function writeSecret(data) {
  const response = http.put(
    testSecretURL(data.runPrefix, __VU),
    JSON.stringify({
      data: {
        run_id: data.runPrefix.split('/').pop(),
        vu: __VU,
        iteration: __ITER,
        payload,
      },
    }),
    {
      headers: {
        'X-Vault-Token': vaultToken,
        'Content-Type': 'application/json',
      },
      responseCallback: http.expectedStatuses(200),
      tags: { operation: 'write_secret' },
    },
  );

  secretWriteDuration.add(response.timings.duration);
  check(response, {
    'KV secret write responds with HTTP 200': (result) => result.status === 200,
  });
}

export function teardown(data) {
  let failures = 0;
  for (let vu = 1; vu <= maxVUs; vu += 1) {
    const response = http.del(testSecretURL(data.runPrefix, vu), null, {
      headers: { 'X-Vault-Token': vaultToken },
      responseCallback: http.expectedStatuses(204),
      tags: { operation: 'cleanup_secret' },
    });
    if (response.status !== 204) {
      failures += 1;
      console.error(`Test secret cleanup failed: vu=${vu} status=${response.status}`);
    }
  }
  if (failures > 0) {
    throw new Error(`Failed to soft-delete ${failures} test secrets`);
  }
}
