namespace MM.Auth;

/// <summary>
/// What a factor produces when enrollment begins. Nothing here is persisted or sealed by the
/// factor itself — the enrollment service owns the secret's lifecycle.
/// </summary>
/// <param name="Kind">Echoes <see cref="IMfaFactor.Kind"/>, so the service can seal it into the token.</param>
/// <param name="PlaintextSecret">
/// Raw secret bytes. Deliberately separate from <paramref name="Data"/>: the service needs bytes
/// to seal, while Data is whatever the host renders verbatim to the user.
/// </param>
/// <param name="Data">Display payload, e.g. <c>{ "otpAuthUri": "...", "secret": "BASE32" }</c>.</param>
public sealed record FactorEnrollStart(
    string Kind,
    byte[] PlaintextSecret,
    IReadOnlyDictionary<string, string> Data);
