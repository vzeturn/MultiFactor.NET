namespace MM.Auth;

/// <summary>
/// One authentication algorithm, and nothing else. A factor never sees ciphertext, never talks
/// to ISecretProtector, and never learns that pending-enroll tokens exist — that
/// is all the enrollment service's job. Adding a factor therefore means implementing two
/// pure functions, not understanding the enrollment lifecycle.
/// </summary>
public interface IMfaFactor
{
    /// <summary>Stable discriminator persisted alongside the secret, e.g. <c>"totp"</c>.</summary>
    string Kind { get; }

    /// <summary>Generates a fresh plaintext secret plus whatever the host should display.</summary>
    Task<FactorEnrollStart> StartEnrollAsync(string subject, CancellationToken ct);

    /// <summary>
    /// Checks one proof against an already-decrypted secret. Used both for the first code at
    /// confirm-enroll time and for every later sign-in.
    /// </summary>
    Task<bool> VerifyAsync(byte[] plaintextSecret, FactorProof proof, CancellationToken ct);
}
