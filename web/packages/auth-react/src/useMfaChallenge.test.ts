import { renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { classifyVerifyError, useMfaChallenge } from './useMfaChallenge.js';
import type { MfaApi } from './types.js';

type Session = { token: string };

function fakeApi(overrides: Partial<MfaApi<Session>> = {}): MfaApi<Session> {
  return {
    status: () => Promise.resolve({ enabled: true }),
    enrollStart: () => Promise.reject(new Error('unused')),
    enrollConfirm: () => Promise.reject(new Error('unused')),
    disable: () => Promise.resolve(undefined),
    verifyMfa: () => Promise.resolve({ token: 'jwt' }),
    emergencyReset: () => Promise.resolve(undefined),
    ...overrides,
  };
}

describe('classifyVerifyError', () => {
  it('maps a 423 verify response to a locked outcome carrying retryAfter', () => {
    expect(classifyVerifyError({ status: 423, retryAfter: 42 })).toEqual({
      ok: false,
      reason: 'locked',
      retryAfter: 42,
    });
  });

  it('reads retryAfter from the response body when the error does not hoist it', () => {
    expect(classifyVerifyError({ status: 423, data: { retryAfter: 900 } })).toEqual({
      ok: false,
      reason: 'locked',
      retryAfter: 900,
    });
  });

  it('omits retryAfter when the lockout carries no window', () => {
    expect(classifyVerifyError({ status: 423 })).toEqual({ ok: false, reason: 'locked' });
  });

  it('maps an expired challenge to expired', () => {
    expect(classifyVerifyError({ status: 410 })).toEqual({ ok: false, reason: 'expired' });
    expect(classifyVerifyError({ status: 419 })).toEqual({ ok: false, reason: 'expired' });
  });

  it('reports anything else as a wrong code', () => {
    expect(classifyVerifyError({ status: 401 })).toEqual({ ok: false, reason: 'wrong_code' });
    expect(classifyVerifyError(new Error('offline'))).toEqual({ ok: false, reason: 'wrong_code' });
    expect(classifyVerifyError(undefined)).toEqual({ ok: false, reason: 'wrong_code' });
  });
});

describe('useMfaChallenge', () => {
  it('returns the login payload on a successful verify', async () => {
    const verifyMfa = vi.fn(() => Promise.resolve({ token: 'jwt' }));
    const { result } = renderHook(() => useMfaChallenge({ api: fakeApi({ verifyMfa }), mfaToken: 'chal-1' }));

    await expect(result.current.verify('123456')).resolves.toEqual({ ok: true, data: { token: 'jwt' } });
    expect(verifyMfa).toHaveBeenCalledWith({ mfaToken: 'chal-1', code: '123456' });
  });

  it('classifies a failing verify instead of throwing', async () => {
    const api = fakeApi({ verifyMfa: () => Promise.reject({ status: 423, retryAfter: 42 }) });
    const { result } = renderHook(() => useMfaChallenge({ api, mfaToken: 'chal-1' }));

    await expect(result.current.verify('000000')).resolves.toEqual({
      ok: false,
      reason: 'locked',
      retryAfter: 42,
    });
  });

  it('reports whether the emergency reset was accepted', async () => {
    const ok = renderHook(() => useMfaChallenge({ api: fakeApi(), mfaToken: 'chal-1' }));
    await expect(ok.result.current.emergencyReset()).resolves.toBe(true);

    const api = fakeApi({ emergencyReset: () => Promise.reject(new Error('nope')) });
    const bad = renderHook(() => useMfaChallenge({ api, mfaToken: 'chal-1' }));
    await expect(bad.result.current.emergencyReset()).resolves.toBe(false);
  });
});
