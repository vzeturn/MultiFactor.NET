import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useMfaEnrollment } from './useMfaEnrollment.js';
import type { MfaApi } from './types.js';

function fakeApi(overrides: Partial<MfaApi> = {}): MfaApi {
  return {
    status: () => Promise.resolve({ enabled: false }),
    enrollStart: () =>
      Promise.resolve({ secret: 'JBSWY3DPEHPK3PXP', otpAuthUri: 'otpauth://totp/x', pendingToken: 'pend-1' }),
    enrollConfirm: () => Promise.resolve({ backupCodes: ['11111111', '22222222'] }),
    disable: () => Promise.resolve(undefined),
    verifyMfa: () => Promise.resolve(undefined),
    emergencyReset: () => Promise.resolve(undefined),
    ...overrides,
  };
}

describe('useMfaEnrollment', () => {
  it('does not report not_enrolled when the status request fails', async () => {
    const onError = vi.fn();
    const api = fakeApi({ status: () => Promise.reject(new Error('offline')) });
    const { result } = renderHook(() => useMfaEnrollment({ api, onError }));

    await waitFor(() => expect(result.current.phase).toBe('error'));
    expect(onError).toHaveBeenCalledWith(expect.any(Error), 'status');
  });

  it('recovers from an error phase when the retry succeeds', async () => {
    let fail = true;
    const api = fakeApi({
      status: () => (fail ? Promise.reject(new Error('offline')) : Promise.resolve({ enabled: true })),
    });
    const { result } = renderHook(() => useMfaEnrollment({ api }));
    await waitFor(() => expect(result.current.phase).toBe('error'));

    fail = false;
    act(() => result.current.retryStatus());
    await waitFor(() => expect(result.current.phase).toBe('enrolled'));
  });

  it('reports enrolled when the status says the account is protected', async () => {
    const { result } = renderHook(() =>
      useMfaEnrollment({ api: fakeApi({ status: () => Promise.resolve({ enabled: true }) }) }),
    );
    await waitFor(() => expect(result.current.phase).toBe('enrolled'));
  });

  it('keeps backup codes until they are explicitly acknowledged', async () => {
    const onEnrolled = vi.fn();
    const { result } = renderHook(() => useMfaEnrollment({ api: fakeApi(), onEnrolled }));
    await waitFor(() => expect(result.current.phase).toBe('not_enrolled'));

    act(() => result.current.start());
    await waitFor(() => expect(result.current.phase).toBe('enrolling'));
    expect(result.current.enrollData?.pendingToken).toBe('pend-1');

    act(() => result.current.confirm('123456'));
    await waitFor(() => expect(result.current.phase).toBe('enrolled'));
    expect(result.current.backupCodes).toEqual(['11111111', '22222222']);
    expect(result.current.enrollData).toBeNull();
    expect(onEnrolled).toHaveBeenCalledTimes(1);

    act(() => result.current.ackBackupCodes());
    expect(result.current.backupCodes).toBeNull();
    expect(result.current.phase).toBe('enrolled');
  });

  it('ignores a confirm issued before an enrollment was started', async () => {
    const enrollConfirm = vi.fn(() => Promise.resolve({ backupCodes: ['1'] }));
    const { result } = renderHook(() => useMfaEnrollment({ api: fakeApi({ enrollConfirm }) }));
    await waitFor(() => expect(result.current.phase).toBe('not_enrolled'));

    act(() => result.current.confirm('123456'));
    expect(enrollConfirm).not.toHaveBeenCalled();
    expect(result.current.confirmPending).toBe(false);
  });

  it('drops the pending enrollment on cancel', async () => {
    const { result } = renderHook(() => useMfaEnrollment({ api: fakeApi() }));
    await waitFor(() => expect(result.current.phase).toBe('not_enrolled'));

    act(() => result.current.start());
    await waitFor(() => expect(result.current.phase).toBe('enrolling'));

    act(() => result.current.cancel());
    expect(result.current.phase).toBe('not_enrolled');
    expect(result.current.enrollData).toBeNull();
  });

  it('stays enrolled and reports the error when disable fails', async () => {
    const onError = vi.fn();
    const onDisabled = vi.fn();
    const api = fakeApi({
      status: () => Promise.resolve({ enabled: true }),
      disable: () => Promise.reject(new Error('wrong code')),
    });
    const { result } = renderHook(() => useMfaEnrollment({ api, onError, onDisabled }));
    await waitFor(() => expect(result.current.phase).toBe('enrolled'));

    act(() => result.current.disable('000000'));
    await waitFor(() => expect(onError).toHaveBeenCalledWith(expect.any(Error), 'disable'));
    expect(result.current.phase).toBe('enrolled');
    expect(onDisabled).not.toHaveBeenCalled();
    await waitFor(() => expect(result.current.disablePending).toBe(false));
  });

  it('returns to not_enrolled after a successful disable', async () => {
    const onDisabled = vi.fn();
    const api = fakeApi({ status: () => Promise.resolve({ enabled: true }) });
    const { result } = renderHook(() => useMfaEnrollment({ api, onDisabled }));
    await waitFor(() => expect(result.current.phase).toBe('enrolled'));

    act(() => result.current.disable('123456'));
    await waitFor(() => expect(result.current.phase).toBe('not_enrolled'));
    expect(onDisabled).toHaveBeenCalledTimes(1);
  });
});
