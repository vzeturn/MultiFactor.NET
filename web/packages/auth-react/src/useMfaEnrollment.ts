import { useCallback, useEffect, useRef, useState } from 'react';
import type { MfaAction, MfaApi, MfaEnrollStartResponse, MfaPhase } from './types.js';

export type UseMfaEnrollmentOptions = {
  api: MfaApi;
  onError?: (error: unknown, action: MfaAction) => void;
  onEnrolled?: () => void;
  onDisabled?: () => void;
};

export type UseMfaEnrollment = {
  phase: MfaPhase;
  enrollData: MfaEnrollStartResponse | null;
  backupCodes: string[] | null;
  startPending: boolean;
  confirmPending: boolean;
  disablePending: boolean;
  start(): void;
  confirm(code: string): void;
  cancel(): void;
  disable(code: string): void;
  retryStatus(): void;
  ackBackupCodes(): void;
};

export function useMfaEnrollment(opts: UseMfaEnrollmentOptions): UseMfaEnrollment {
  const [phase, setPhase] = useState<MfaPhase>('loading');
  const [enrollData, setEnrollData] = useState<MfaEnrollStartResponse | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [startPending, setStartPending] = useState(false);
  const [confirmPending, setConfirmPending] = useState(false);
  const [disablePending, setDisablePending] = useState(false);

  const optsRef = useRef(opts);
  const enrollDataRef = useRef(enrollData);
  enrollDataRef.current = enrollData;
  const alive = useRef(true);
  useEffect(() => {
    optsRef.current = opts;
  });
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const fail = (error: unknown, action: MfaAction) => optsRef.current.onError?.(error, action);

  const loadStatus = useCallback(async () => {
    setPhase('loading');
    try {
      const status = await optsRef.current.api.status();
      if (!alive.current) return;
      setPhase(status.enabled ? 'enrolled' : 'not_enrolled');
    } catch (error) {
      if (!alive.current) return;
      // Unknown must render as unknown, never as not_enrolled: telling an admin the
      // account is unprotected when it may be enrolled is the bug this phase prevents.
      setPhase('error');
      fail(error, 'status');
    }
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  const start = useCallback(() => {
    setStartPending(true);
    void (async () => {
      try {
        const data = await optsRef.current.api.enrollStart();
        if (!alive.current) return;
        setEnrollData(data);
        setPhase('enrolling');
      } catch (error) {
        if (alive.current) fail(error, 'start');
      } finally {
        if (alive.current) setStartPending(false);
      }
    })();
  }, []);

  const confirm = useCallback((code: string) => {
    const pending = enrollDataRef.current;
    if (!pending) return;
    setConfirmPending(true);
    void (async () => {
      try {
        const data = await optsRef.current.api.enrollConfirm({ pendingToken: pending.pendingToken, code });
        if (!alive.current) return;
        setBackupCodes(data.backupCodes);
        setEnrollData(null);
        setPhase('enrolled');
        optsRef.current.onEnrolled?.();
      } catch (error) {
        if (alive.current) fail(error, 'confirm');
      } finally {
        if (alive.current) setConfirmPending(false);
      }
    })();
  }, []);

  const disable = useCallback((code: string) => {
    setDisablePending(true);
    void (async () => {
      try {
        await optsRef.current.api.disable({ code });
        if (!alive.current) return;
        setPhase('not_enrolled');
        optsRef.current.onDisabled?.();
      } catch (error) {
        if (alive.current) fail(error, 'disable');
      } finally {
        if (alive.current) setDisablePending(false);
      }
    })();
  }, []);

  const cancel = useCallback(() => {
    setEnrollData(null);
    setPhase('not_enrolled');
  }, []);

  const ackBackupCodes = useCallback(() => setBackupCodes(null), []);
  const retryStatus = useCallback(() => void loadStatus(), [loadStatus]);

  return {
    phase,
    enrollData,
    backupCodes,
    startPending,
    confirmPending,
    disablePending,
    start,
    confirm,
    cancel,
    disable,
    retryStatus,
    ackBackupCodes,
  };
}
