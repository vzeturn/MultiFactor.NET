import { useCallback, useEffect, useRef } from 'react';
import type { MfaApi, MfaVerifyFailure, MfaVerifyOutcome } from './types.js';

export type UseMfaChallengeOptions<TLogin> = {
  api: MfaApi<TLogin>;
  mfaToken: string;
};

export type UseMfaChallenge<TLogin> = {
  verify(code: string): Promise<MfaVerifyOutcome<TLogin>>;
  emergencyReset(): Promise<boolean>;
};

type HttpLike = { status?: number; retryAfter?: number; data?: { retryAfter?: number } };

/**
 * A 423 carries the host lockout window; anything else that is not an outright
 * expiry is reported as a wrong code so the caller never leaks which one it was.
 */
export function classifyVerifyError(error: unknown): MfaVerifyFailure {
  const e = (error ?? {}) as HttpLike;
  if (e.status === 423) {
    const retryAfter = e.retryAfter ?? e.data?.retryAfter;
    return retryAfter === undefined ? { ok: false, reason: 'locked' } : { ok: false, reason: 'locked', retryAfter };
  }
  if (e.status === 410 || e.status === 419) return { ok: false, reason: 'expired' };
  return { ok: false, reason: 'wrong_code' };
}

export function useMfaChallenge<TLogin = unknown>(
  opts: UseMfaChallengeOptions<TLogin>,
): UseMfaChallenge<TLogin> {
  const optsRef = useRef(opts);
  useEffect(() => {
    optsRef.current = opts;
  });

  const verify = useCallback(async (code: string): Promise<MfaVerifyOutcome<TLogin>> => {
    const { api, mfaToken } = optsRef.current;
    try {
      return { ok: true, data: await api.verifyMfa({ mfaToken, code }) };
    } catch (error) {
      return classifyVerifyError(error);
    }
  }, []);

  const emergencyReset = useCallback(async (): Promise<boolean> => {
    const { api, mfaToken } = optsRef.current;
    try {
      await api.emergencyReset(mfaToken);
      return true;
    } catch {
      return false;
    }
  }, []);

  return { verify, emergencyReset };
}
