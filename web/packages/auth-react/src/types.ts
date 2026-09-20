export type MfaStatusResponse = { enabled: boolean };
export type MfaEnrollStartResponse = { secret: string; otpAuthUri: string; pendingToken: string };
export type MfaEnrollConfirmRequest = { pendingToken: string; code: string };
export type MfaEnrollConfirmResponse = { backupCodes: string[] };
export type MfaDisableRequest = { code: string };

/**
 * POST /login answers with this shape directly - HTTP 202, no envelope - when the
 * account has MFA enabled. The host transport must not unwrap it.
 */
export type MfaChallengeResponse = { mfaRequired: boolean; mfaToken: string; expiresInSeconds: number };
export type VerifyMfaRequest = { mfaToken: string; code: string };

export type MfaPhase = 'loading' | 'not_enrolled' | 'enrolling' | 'enrolled' | 'error';

export type MfaAction = 'status' | 'start' | 'confirm' | 'disable';

export type MfaTransport = {
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
};

export type MfaApi<TLogin = unknown> = {
  status(): Promise<MfaStatusResponse>;
  enrollStart(): Promise<MfaEnrollStartResponse>;
  enrollConfirm(body: MfaEnrollConfirmRequest): Promise<MfaEnrollConfirmResponse>;
  disable(body: MfaDisableRequest): Promise<unknown>;
  verifyMfa(body: VerifyMfaRequest): Promise<TLogin>;
  emergencyReset(mfaToken: string): Promise<unknown>;
};

export type MfaVerifyFailure = {
  ok: false;
  reason: 'wrong_code' | 'expired' | 'locked';
  retryAfter?: number;
};

export type MfaVerifyOutcome<TLogin = unknown> = { ok: true; data: TLogin } | MfaVerifyFailure;
