using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace MM.Auth;

/// <summary>
/// The single place that seals secrets, dispatches to factors, and owns the parts of MFA that are
/// the same whatever the factor is.
/// </summary>
public sealed class MfaFactorService(
    IEnumerable<IMfaFactor> factors,
    IMfaRepository repository,
    ISecretProtector protector,
    MfaOptions options) : IMfaFactorService
{
    private const string PendingContext = "pending";
    private const string SecretContext = "secret";
    private const int PayloadFieldCount = 4;

    private readonly IReadOnlyList<IMfaFactor> _factors = [.. factors];

    private IMfaFactor Factor(string factorKind) =>
        _factors.FirstOrDefault(f => f.Kind == factorKind)
        ?? throw new InvalidOperationException(
            "No IMfaFactor is registered for kind '" + factorKind + "'. Registered kinds: " +
            (_factors.Count == 0 ? "(none)" : string.Join(", ", _factors.Select(f => f.Kind))) + ".");

    public Task<bool> IsEnabledAsync(string subject, string factorKind, CancellationToken ct = default) =>
        repository.IsEnabledAsync(subject, factorKind, ct);

    public async Task<MfaEnrollStart> StartEnrollAsync(
        string subject, string factorKind, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        var factor = Factor(factorKind);
        var started = await factor.StartEnrollAsync(subject, ct).ConfigureAwait(false);

        var expiry = DateTimeOffset.UtcNow.Add(options.PendingEnrollLifetime).ToUnixTimeSeconds();
        var payload = subject + "|" + factorKind + "|" +
                      Convert.ToBase64String(started.PlaintextSecret) + "|" +
                      expiry.ToString(CultureInfo.InvariantCulture);

        var sealedBytes = await protector
            .ProtectAsync(Encoding.UTF8.GetBytes(payload), PendingContext, ct)
            .ConfigureAwait(false);

        return new MfaEnrollStart(started.Kind, ToBase64Url(sealedBytes), started.Data);
    }

    /// <summary>
    /// Blocks on the async protector, deliberately and only here. <see cref="ISecretProtector"/> is
    /// async because key providers can be remote, but this method exists as a cheap synchronous
    /// convenience for callers that already hold the token and just want to know whose it is
    /// (typically an authorization filter). It is the one place in this library that pays the
    /// sync-over-async cost; every other path awaits. A host whose key provider does real I/O and
    /// runs under a constrained SynchronizationContext should call
    /// <see cref="ConfirmEnrollAsync"/> instead of relying on this.
    /// </summary>
    /// <param name="pendingToken">The sealed token returned by <see cref="StartEnrollAsync"/>.</param>
    public string? PeekPendingSubject(string pendingToken)
    {
        try
        {
            var payload = protector
                .UnprotectAsync(FromBase64Url(pendingToken), PendingContext)
                .AsTask().GetAwaiter().GetResult();
            var parsed = ParsePayload(payload);
            if (parsed is null || parsed.Value.Expiry < DateTimeOffset.UtcNow) return null;
            return parsed.Value.Subject;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or OverflowException)
        {
            return null;
        }
    }

    public async Task<FactorEnrollResult> ConfirmEnrollAsync(
        string pendingToken, FactorProof proof, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(proof);

        byte[] payload;
        try
        {
            payload = await protector
                .UnprotectAsync(FromBase64Url(pendingToken), PendingContext, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or OverflowException)
        {
            // A forged or foreign token is indistinguishable from a wrong code at this layer, and
            // saying which it was would confirm to an attacker that their token parsed.
            return new FactorEnrollResult.InvalidProof();
        }

        var parsed = ParsePayload(payload);
        if (parsed is null) return new FactorEnrollResult.InvalidProof();
        var (subject, factorKind, secret, expiry) = parsed.Value;
        if (expiry < DateTimeOffset.UtcNow) return new FactorEnrollResult.Expired();

        var factor = Factor(factorKind);
        if (!await factor.VerifyAsync(secret, proof, ct).ConfigureAwait(false))
            return new FactorEnrollResult.InvalidProof();

        var backupCodes = GenerateBackupCodes(options.BackupCodeCount);
        var encrypted = await protector.ProtectAsync(secret, SecretContext, ct).ConfigureAwait(false);
        await repository.EnrollAsync(subject, factorKind, encrypted, backupCodes, ct).ConfigureAwait(false);
        return new FactorEnrollResult.Success(backupCodes);
    }

    public async Task<bool> VerifyAsync(string subject, FactorProof proof, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(proof);

        foreach (var factor in _factors)
        {
            if (!await repository.IsEnabledAsync(subject, factor.Kind, ct).ConfigureAwait(false)) continue;

            var encrypted = await repository.GetSecretAsync(subject, factor.Kind, ct).ConfigureAwait(false);
            if (encrypted is null) continue;

            var secret = await protector.UnprotectAsync(encrypted, SecretContext, ct).ConfigureAwait(false);
            if (await factor.VerifyAsync(secret, proof, ct).ConfigureAwait(false)) return true;
        }

        return proof is FactorProof.Code code &&
               await repository.TryConsumeBackupCodeAsync(subject, code.Value, ct).ConfigureAwait(false);
    }

    public Task DisableAsync(string subject, string factorKind, CancellationToken ct = default) =>
        repository.DisableAsync(subject, factorKind, ct);

    public Task<int> CountRemainingBackupCodesAsync(string subject, CancellationToken ct = default) =>
        repository.CountRemainingBackupCodesAsync(subject, ct);

    public async Task<MfaChallenge> CreateChallengeAsync(
        string subject, int scope, CancellationToken ct = default)
    {
        var token = await repository.CreateChallengeAsync(subject, scope, ct).ConfigureAwait(false);
        return new MfaChallenge(token, (int)options.ChallengeLifetime.TotalSeconds);
    }

    public Task<MfaChallengeSubject?> ConsumeChallengeAsync(
        string challengeToken, CancellationToken ct = default) =>
        repository.TryConsumeChallengeAsync(challengeToken, ct);

    /// <summary>Distinct 8-digit codes, drawn from a cryptographic RNG.</summary>
    private static IReadOnlyList<string> GenerateBackupCodes(int count)
    {
        var codes = new HashSet<string>(count);
        while (codes.Count < count)
        {
            var value = RandomNumberGenerator.GetInt32(0, 100_000_000);
            codes.Add(value.ToString("D8", CultureInfo.InvariantCulture));
        }
        return [.. codes];
    }

    private static (string Subject, string FactorKind, byte[] Secret, DateTimeOffset Expiry)? ParsePayload(
        byte[] payload)
    {
        var parts = Encoding.UTF8.GetString(payload).Split('|');
        if (parts.Length != PayloadFieldCount) return null;
        if (!long.TryParse(parts[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out var unix))
            return null;
        return (parts[0], parts[1], Convert.FromBase64String(parts[2]),
            DateTimeOffset.FromUnixTimeSeconds(unix));
    }

    private static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static byte[] FromBase64Url(string token)
    {
        ArgumentNullException.ThrowIfNull(token);
        var padded = token.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }
}
