using System.Security.Cryptography;
using System.Text;

namespace MM.Auth.Tests;

/// <summary>
/// In-memory repository. Mirrors the observable behaviour SqliteMfaRepository must also satisfy:
/// enroll replaces that factor's secret and all of the subject's backup codes; disable removes
/// only the named factor plus the codes.
/// </summary>
public sealed class FakeRepository : IMfaRepository
{
    private readonly Dictionary<(string Subject, string Kind), byte[]> _secrets = [];
    private readonly Dictionary<string, List<BackupCode>> _codes = [];
    private readonly Dictionary<string, ChallengeRow> _challenges = [];

    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    private sealed class BackupCode
    {
        public required string Value { get; init; }
        public bool Used { get; set; }
    }

    private sealed class ChallengeRow
    {
        public required string Subject { get; init; }
        public required int Scope { get; init; }
        public required DateTimeOffset ExpiresAt { get; init; }
        public bool Consumed { get; set; }
    }

    public Task<bool> IsEnabledAsync(string subject, string factorKind, CancellationToken ct = default) =>
        Task.FromResult(_secrets.ContainsKey((subject, factorKind)));

    public Task<byte[]?> GetSecretAsync(string subject, string factorKind, CancellationToken ct = default) =>
        Task.FromResult(_secrets.TryGetValue((subject, factorKind), out var secret) ? secret : null);

    public Task EnrollAsync(string subject, string factorKind, byte[] encryptedSecret,
        IReadOnlyList<string> backupCodes, CancellationToken ct = default)
    {
        _secrets[(subject, factorKind)] = encryptedSecret;
        _codes[subject] = [.. backupCodes.Select(c => new BackupCode { Value = c })];
        return Task.CompletedTask;
    }

    public Task DisableAsync(string subject, string factorKind, CancellationToken ct = default)
    {
        _secrets.Remove((subject, factorKind));
        _codes.Remove(subject);
        return Task.CompletedTask;
    }

    public Task<bool> TryConsumeBackupCodeAsync(string subject, string code, CancellationToken ct = default)
    {
        if (!_codes.TryGetValue(subject, out var codes)) return Task.FromResult(false);
        var match = codes.FirstOrDefault(c => !c.Used && c.Value == code);
        if (match is null) return Task.FromResult(false);
        match.Used = true;
        return Task.FromResult(true);
    }

    public Task<int> CountRemainingBackupCodesAsync(string subject, CancellationToken ct = default) =>
        Task.FromResult(_codes.TryGetValue(subject, out var codes) ? codes.Count(c => !c.Used) : 0);

    public Task<string> CreateChallengeAsync(string subject, int scope, CancellationToken ct = default)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        _challenges[token] = new ChallengeRow
        {
            Subject = subject,
            Scope = scope,
            ExpiresAt = DateTimeOffset.UtcNow.Add(ChallengeLifetime),
        };
        return Task.FromResult(token);
    }

    public Task<MfaChallengeSubject?> TryConsumeChallengeAsync(
        string challengeToken, CancellationToken ct = default)
    {
        if (!_challenges.TryGetValue(challengeToken, out var row)) return Task.FromResult<MfaChallengeSubject?>(null);
        if (row.Consumed || row.ExpiresAt <= DateTimeOffset.UtcNow)
            return Task.FromResult<MfaChallengeSubject?>(null);
        row.Consumed = true;
        return Task.FromResult<MfaChallengeSubject?>(new MfaChallengeSubject(row.Subject, row.Scope));
    }
}

/// <summary>
/// Reversible stand-in for a real protector: it prefixes the context and XORs the payload, which is
/// enough to prove the service binds the right context and never mixes "pending" with "secret"
/// blobs, without pulling AES into the core test project.
/// </summary>
public sealed class FakeProtector : ISecretProtector
{
    private const byte Mask = 0x5A;

    public ValueTask<byte[]> ProtectAsync(byte[] plaintext, string context, CancellationToken ct = default)
    {
        var label = Encoding.UTF8.GetBytes(context);
        var blob = new byte[1 + label.Length + plaintext.Length];
        blob[0] = (byte)label.Length;
        label.CopyTo(blob, 1);
        for (var i = 0; i < plaintext.Length; i++) blob[1 + label.Length + i] = (byte)(plaintext[i] ^ Mask);
        return ValueTask.FromResult(blob);
    }

    public ValueTask<byte[]> UnprotectAsync(byte[] ciphertext, string context, CancellationToken ct = default)
    {
        if (ciphertext.Length < 1) throw new CryptographicException("Empty blob.");
        var labelLength = ciphertext[0];
        if (ciphertext.Length < 1 + labelLength) throw new CryptographicException("Truncated blob.");
        var label = Encoding.UTF8.GetString(ciphertext, 1, labelLength);
        if (label != context) throw new CryptographicException("Context mismatch.");
        var payload = new byte[ciphertext.Length - 1 - labelLength];
        for (var i = 0; i < payload.Length; i++) payload[i] = (byte)(ciphertext[1 + labelLength + i] ^ Mask);
        return ValueTask.FromResult(payload);
    }
}

/// <summary>
/// A factor whose secret is a UTF-8 string and whose proof is that same string. Lets the
/// orchestration tests assert on exact secrets without computing real TOTP codes.
/// </summary>
public sealed class FakeFactor(string kind, string secret) : IMfaFactor
{
    public string Kind { get; } = kind;

    public int VerifyCallCount { get; private set; }

    public Task<FactorEnrollStart> StartEnrollAsync(string subject, CancellationToken ct) =>
        Task.FromResult(new FactorEnrollStart(
            Kind,
            Encoding.UTF8.GetBytes(secret),
            new Dictionary<string, string> { ["subject"] = subject, ["kind"] = Kind }));

    public Task<bool> VerifyAsync(byte[] plaintextSecret, FactorProof proof, CancellationToken ct)
    {
        VerifyCallCount++;
        return Task.FromResult(
            proof is FactorProof.Code code && code.Value == Encoding.UTF8.GetString(plaintextSecret));
    }
}
