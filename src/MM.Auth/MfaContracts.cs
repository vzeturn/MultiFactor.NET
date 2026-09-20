namespace MM.Auth;

/// <param name="Token">Opaque single-use login challenge token.</param>
/// <param name="ExpiresInSeconds">Whole seconds of <see cref="MfaOptions.ChallengeLifetime"/>.</param>
public sealed record MfaChallenge(string Token, int ExpiresInSeconds);

/// <param name="Subject">The authenticated principal identifier the challenge was issued for.</param>
/// <param name="Scope">Opaque host-supplied integer carried through the challenge.</param>
public sealed record MfaChallengeSubject(string Subject, int Scope);

/// <summary>
/// Result of starting enrollment at the service layer. <paramref name="PendingToken"/> is sealed by
/// <c>MfaFactorService</c>; <paramref name="Kind"/> and <paramref name="Data"/> come verbatim
/// from the factor's <see cref="FactorEnrollStart"/>. The plaintext secret never appears here.
/// </summary>
public sealed record MfaEnrollStart(
    string Kind,
    string PendingToken,
    IReadOnlyDictionary<string, string> Data);
