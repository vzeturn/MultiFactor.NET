namespace MM.Auth;

/// <summary>
/// What a user presents to prove possession of a factor. A closed union rather than a bare
/// string, because not every factor is a typed-in code: WebAuthn presents raw assertion bytes.
/// </summary>
public abstract record FactorProof
{
    private FactorProof() { }

    /// <summary>A typed-in code. TOTP and backup codes both use this case.</summary>
    public sealed record Code(string Value) : FactorProof;

    /// <summary>Opaque assertion bytes, for future signature-based factors.</summary>
    public sealed record Assertion(byte[] Value) : FactorProof;
}
