using System.Security.Cryptography;
using OtpNet;

namespace MM.Auth.Totp;

/// <summary>
/// RFC 6238 time-based one-time passwords: SHA-1, 6 digits, 30-second step, ±1 step of tolerance
/// for clock skew — the parameters every mainstream authenticator app assumes.
/// </summary>
public sealed class TotpFactor(MfaOptions options) : IMfaFactor
{
    /// <summary>The RFC 6238 recommended secret size.</summary>
    private const int SecretBytes = 20;

    private const int Step = 30;
    private const int Digits = 6;

    public string Kind => "totp";

    public Task<FactorEnrollStart> StartEnrollAsync(string subject, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var secret = RandomNumberGenerator.GetBytes(SecretBytes);
        var base32 = Base32Encoding.ToString(secret);

        var data = new Dictionary<string, string>
        {
            // Base32 form, for manual entry when the QR cannot be scanned.
            ["secret"] = base32,
            ["otpAuthUri"] = BuildOtpAuthUri(base32, subject),
        };

        return Task.FromResult(new FactorEnrollStart(Kind, secret, data));
    }

    public Task<bool> VerifyAsync(byte[] plaintextSecret, FactorProof proof, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(plaintextSecret);

        if (proof is not FactorProof.Code code) return Task.FromResult(false);
        if (string.IsNullOrWhiteSpace(code.Value)) return Task.FromResult(false);

        var totp = new OtpNet.Totp(plaintextSecret, step: Step, mode: OtpHashMode.Sha1, totpSize: Digits);
        return Task.FromResult(
            totp.VerifyTotp(code.Value, out _, new VerificationWindow(previous: 1, future: 1)));
    }

    private string BuildOtpAuthUri(string base32Secret, string accountLabel)
    {
        var label = Uri.EscapeDataString(options.Issuer + ":" + accountLabel);
        var issuer = Uri.EscapeDataString(options.Issuer);
        return "otpauth://totp/" + label + "?secret=" + base32Secret +
               "&issuer=" + issuer + "&digits=" + Digits + "&period=" + Step;
    }
}
