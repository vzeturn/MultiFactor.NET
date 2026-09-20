import { describe, expect, it } from 'vitest';
import { createMfaApi, DEFAULT_MFA_BASE_PATH } from './createMfaApi.js';
import type { MfaTransport } from './types.js';

type Call = { verb: 'get' | 'post'; path: string; body?: unknown };

function recorder() {
  const calls: Call[] = [];
  const transport: MfaTransport = {
    get: async <T,>(path: string) => {
      calls.push({ verb: 'get', path });
      return {} as T;
    },
    post: async <T,>(path: string, body?: unknown) => {
      calls.push({ verb: 'post', path, body });
      return {} as T;
    },
  };
  return { calls, transport };
}

describe('createMfaApi', () => {
  it('routes every call under the default auth base path', async () => {
    const { calls, transport } = recorder();
    const api = createMfaApi(transport);

    await api.status();
    await api.enrollStart();
    await api.enrollConfirm({ pendingToken: 'p', code: '123456' });
    await api.disable({ code: '123456' });
    await api.verifyMfa({ mfaToken: 'm', code: '123456' });
    await api.emergencyReset('m');

    expect(calls.map((c) => c.verb + ' ' + c.path)).toEqual([
      'get /api/v1/auth/mfa/status',
      'post /api/v1/auth/mfa/enroll/start',
      'post /api/v1/auth/mfa/enroll/confirm',
      'post /api/v1/auth/mfa/disable',
      'post /api/v1/auth/login/verify-mfa',
      'post /api/v1/auth/login/mfa-emergency-reset',
    ]);
    expect(DEFAULT_MFA_BASE_PATH).toBe('/api/v1/auth');
  });

  it('sends the emergency reset token with an empty code', async () => {
    const { calls, transport } = recorder();
    await createMfaApi(transport).emergencyReset('tok-42');
    expect(calls[0]?.body).toEqual({ mfaToken: 'tok-42', code: '' });
  });

  it('honours a host supplied base path', async () => {
    const { calls, transport } = recorder();
    await createMfaApi(transport, '/backoffice/auth').status();
    expect(calls[0]?.path).toBe('/backoffice/auth/mfa/status');
  });
});
