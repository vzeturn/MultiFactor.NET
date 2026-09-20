namespace MM.Auth;

/// <summary>
/// An operational crypto failure — unreadable blob format, or a key the host can no longer
/// supply. Distinct from a plain <see cref="System.Security.Cryptography.CryptographicException"/>
/// (which a wrong key or tampered blob raises) so a host can alert on "our key management is
/// broken" without alerting on "a user mistyped a code".
/// </summary>
public sealed class SecretProtectionException(string message, Exception? inner = null)
    : System.Security.Cryptography.CryptographicException(message, inner);
