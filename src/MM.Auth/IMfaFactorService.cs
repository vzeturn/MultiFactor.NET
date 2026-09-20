namespace MM.Auth;

/// <summary>
/// Orchestration across every registered <see cref="IMfaFactor"/>: it owns secret sealing, backup
/// codes, challenges and enable/disable, so an individual factor never has to.
/// </summary>
public interface IMfaFactorService
{
    Task<bool> IsEnabledAsync(string subject, string factorKind, CancellationToken ct = default);

    /// <summary>
    /// Returns a service-sealed pending token plus the factor's display data. Nothing is persisted
    /// until <see cref="ConfirmEnrollAsync"/> succeeds, so an abandoned enrollment leaves no trace
    /// and cannot half-enable MFA.
    /// </summary>
    Task<MfaEnrollStart> StartEnrollAsync(string subject, string factorKind, CancellationToken ct = default);

    Task<FactorEnrollResult> ConfirmEnrollAsync(string pendingToken, FactorProof proof, CancellationToken ct = default);

    /// <summary>
    /// Subject a pending token was issued to, or null if it is malformed, tampered with or expired.
    /// Lets a host reject somebody else's token before confirming it; the secret never leaves.
    /// </summary>
    string? PeekPendingSubject(string pendingToken);

    /// <summary>
    /// Verifies the subject's enabled factor, falling back to a backup code when the proof is a
    /// <see cref="FactorProof.Code"/> that no factor accepted.
    /// </summary>
    Task<bool> VerifyAsync(string subject, FactorProof proof, CancellationToken ct = default);

    Task DisableAsync(string subject, string factorKind, CancellationToken ct = default);

    Task<int> CountRemainingBackupCodesAsync(string subject, CancellationToken ct = default);

    Task<MfaChallenge> CreateChallengeAsync(string subject, int scope, CancellationToken ct = default);

    Task<MfaChallengeSubject?> ConsumeChallengeAsync(string challengeToken, CancellationToken ct = default);
}
