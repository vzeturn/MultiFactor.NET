import type {
  MfaApi,
  MfaDisableRequest,
  MfaEnrollConfirmRequest,
  MfaEnrollConfirmResponse,
  MfaEnrollStartResponse,
  MfaStatusResponse,
  MfaTransport,
  VerifyMfaRequest,
} from './types.js';

export const DEFAULT_MFA_BASE_PATH = '/api/v1/auth';

export function createMfaApi<TLogin = unknown>(
  transport: MfaTransport,
  basePath: string = DEFAULT_MFA_BASE_PATH,
): MfaApi<TLogin> {
  const at = (path: string) => basePath + path;
  return {
    status: () => transport.get<MfaStatusResponse>(at('/mfa/status')),
    enrollStart: () => transport.post<MfaEnrollStartResponse>(at('/mfa/enroll/start')),
    enrollConfirm: (body: MfaEnrollConfirmRequest) =>
      transport.post<MfaEnrollConfirmResponse>(at('/mfa/enroll/confirm'), body),
    disable: (body: MfaDisableRequest) => transport.post<unknown>(at('/mfa/disable'), body),
    verifyMfa: (body: VerifyMfaRequest) => transport.post<TLogin>(at('/login/verify-mfa'), body),
    emergencyReset: (mfaToken: string) =>
      transport.post<unknown>(at('/login/mfa-emergency-reset'), { mfaToken, code: '' }),
  };
}
