using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Dapper;

namespace MM.Auth.Sqlite;

/// <summary>
/// SQLite storage for MM.Auth. Stores the ciphertext it is handed verbatim: this adapter has no
/// knowledge of, and no dependency on, ISecretProtector.
/// </summary>
/// <remarks>
/// Every timestamp is computed here in C# and bound as a parameter, in a sortable UTC ISO-8601
/// form, so the SQL text itself contains no engine-specific date functions.
/// </remarks>
public sealed class SqliteMfaRepository : IMfaRepository
{
    private const string TimestampFormat = "yyyy-MM-ddTHH:mm:ssZ";

    private readonly IMfaConnectionFactory _factory;
    private readonly TimeSpan _challengeLifetime;

    private readonly string _sqlIsEnabled;
    private readonly string _sqlGetSecret;
    private readonly string _sqlDeleteSecret;
    private readonly string _sqlDeleteBackupCodes;
    private readonly string _sqlInsertSecret;
    private readonly string _sqlInsertBackupCode;
    private readonly string _sqlTryConsumeBackupCode;
    private readonly string _sqlCountRemainingBackupCodes;
    private readonly string _sqlInsertChallenge;
    private readonly string _sqlTryConsumeChallenge;
    private readonly string _sqlGetChallenge;

    public SqliteMfaRepository(IMfaConnectionFactory factory, MfaOptions options)
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(options);
        _factory = factory;
        _challengeLifetime = options.ChallengeLifetime;

        var secret = options.Table("secret");
        var backup = options.Table("backup_code");
        var challenge = options.Table("challenge");

        _sqlIsEnabled =
            "SELECT COUNT(*) FROM " + secret +
            " WHERE initial = @Subject AND factor_kind = @FactorKind AND enabled = 1";
        _sqlGetSecret =
            "SELECT secret_encrypted FROM " + secret +
            " WHERE initial = @Subject AND factor_kind = @FactorKind AND enabled = 1";
        _sqlDeleteSecret =
            "DELETE FROM " + secret + " WHERE initial = @Subject AND factor_kind = @FactorKind";
        _sqlDeleteBackupCodes = "DELETE FROM " + backup + " WHERE initial = @Subject";
        _sqlInsertSecret =
            "INSERT INTO " + secret +
            " (initial, factor_kind, secret_encrypted, enrolled_at, enabled) " +
            "VALUES (@Subject, @FactorKind, @Secret, @Now, 1)";
        _sqlInsertBackupCode =
            "INSERT INTO " + backup + " (initial, code_hash, created_at) VALUES (@Subject, @Hash, @Now)";
        _sqlTryConsumeBackupCode =
            "UPDATE " + backup + " SET used_at = @Now " +
            "WHERE initial = @Subject AND code_hash = @Hash AND used_at IS NULL";
        _sqlCountRemainingBackupCodes =
            "SELECT COUNT(*) FROM " + backup + " WHERE initial = @Subject AND used_at IS NULL";
        _sqlInsertChallenge =
            "INSERT INTO " + challenge +
            " (challenge_token, initial, rvc, created_at, expires_at) " +
            "VALUES (@Token, @Subject, @Scope, @Now, @ExpiresAt)";
        _sqlTryConsumeChallenge =
            "UPDATE " + challenge + " SET consumed_at = @Now " +
            "WHERE challenge_token = @Token AND consumed_at IS NULL AND expires_at > @Now";
        _sqlGetChallenge =
            "SELECT initial AS Subject, rvc AS Scope FROM " + challenge + " WHERE challenge_token = @Token";
    }

    private static string Stamp(DateTimeOffset at) =>
        at.UtcDateTime.ToString(TimestampFormat, CultureInfo.InvariantCulture);

    private static string Now() => Stamp(DateTimeOffset.UtcNow);

    private static string HashCode(string code) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code)));

    public async Task<bool> IsEnabledAsync(
        string subject, string factorKind, CancellationToken ct = default)
    {
        await using var conn = await _factory.CreateOpenAsync(ct).ConfigureAwait(false);
        var count = await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            _sqlIsEnabled,
            new { Subject = subject, FactorKind = factorKind },
            cancellationToken: ct)).ConfigureAwait(false);
        return count > 0;
    }

    public async Task<byte[]?> GetSecretAsync(
        string subject, string factorKind, CancellationToken ct = default)
    {
        await using var conn = await _factory.CreateOpenAsync(ct).ConfigureAwait(false);
        return await conn.QuerySingleOrDefaultAsync<byte[]?>(new CommandDefinition(
            _sqlGetSecret,
            new { Subject = subject, FactorKind = factorKind },
            cancellationToken: ct)).ConfigureAwait(false);
    }

    public async Task EnrollAsync(
        string subject, string factorKind, byte[] encryptedSecret,
        IReadOnlyList<string> backupCodes, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(encryptedSecret);
        ArgumentNullException.ThrowIfNull(backupCodes);

        var now = Now();
        await using var conn = await _factory.CreateOpenAsync(ct).ConfigureAwait(false);
        await using var tx = await conn.BeginTransactionAsync(ct).ConfigureAwait(false);

        await conn.ExecuteAsync(new CommandDefinition(
            _sqlDeleteBackupCodes, new { Subject = subject }, tx, cancellationToken: ct))
            .ConfigureAwait(false);
        await conn.ExecuteAsync(new CommandDefinition(
            _sqlDeleteSecret, new { Subject = subject, FactorKind = factorKind }, tx, cancellationToken: ct))
            .ConfigureAwait(false);

        await conn.ExecuteAsync(new CommandDefinition(
            _sqlInsertSecret,
            new { Subject = subject, FactorKind = factorKind, Secret = encryptedSecret, Now = now },
            tx, cancellationToken: ct)).ConfigureAwait(false);

        foreach (var code in backupCodes)
        {
            await conn.ExecuteAsync(new CommandDefinition(
                _sqlInsertBackupCode,
                new { Subject = subject, Hash = HashCode(code), Now = now },
                tx, cancellationToken: ct)).ConfigureAwait(false);
        }

        await tx.CommitAsync(ct).ConfigureAwait(false);
    }

    public async Task DisableAsync(string subject, string factorKind, CancellationToken ct = default)
    {
        await using var conn = await _factory.CreateOpenAsync(ct).ConfigureAwait(false);
        await using var tx = await conn.BeginTransactionAsync(ct).ConfigureAwait(false);
        await conn.ExecuteAsync(new CommandDefinition(
            _sqlDeleteBackupCodes, new { Subject = subject }, tx, cancellationToken: ct))
            .ConfigureAwait(false);
        await conn.ExecuteAsync(new CommandDefinition(
            _sqlDeleteSecret, new { Subject = subject, FactorKind = factorKind }, tx, cancellationToken: ct))
            .ConfigureAwait(false);
        await tx.CommitAsync(ct).ConfigureAwait(false);
    }

    public async Task<bool> TryConsumeBackupCodeAsync(
        string subject, string code, CancellationToken ct = default)
    {
        await using var conn = await _factory.CreateOpenAsync(ct).ConfigureAwait(false);
        var rows = await conn.ExecuteAsync(new CommandDefinition(
            _sqlTryConsumeBackupCode,
            new { Subject = subject, Hash = HashCode(code), Now = Now() },
            cancellationToken: ct)).ConfigureAwait(false);
        return rows > 0;
    }

    public async Task<int> CountRemainingBackupCodesAsync(
        string subject, CancellationToken ct = default)
    {
        await using var conn = await _factory.CreateOpenAsync(ct).ConfigureAwait(false);
        return await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            _sqlCountRemainingBackupCodes, new { Subject = subject }, cancellationToken: ct))
            .ConfigureAwait(false);
    }

    public async Task<string> CreateChallengeAsync(
        string subject, int scope, CancellationToken ct = default)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var now = DateTimeOffset.UtcNow;
        await using var conn = await _factory.CreateOpenAsync(ct).ConfigureAwait(false);
        await conn.ExecuteAsync(new CommandDefinition(
            _sqlInsertChallenge,
            new
            {
                Token = token,
                Subject = subject,
                Scope = scope,
                Now = Stamp(now),
                ExpiresAt = Stamp(now.Add(_challengeLifetime)),
            },
            cancellationToken: ct)).ConfigureAwait(false);
        return token;
    }

    public async Task<MfaChallengeSubject?> TryConsumeChallengeAsync(
        string challengeToken, CancellationToken ct = default)
    {
        await using var conn = await _factory.CreateOpenAsync(ct).ConfigureAwait(false);
        var rows = await conn.ExecuteAsync(new CommandDefinition(
            _sqlTryConsumeChallenge,
            new { Token = challengeToken, Now = Now() },
            cancellationToken: ct)).ConfigureAwait(false);
        if (rows == 0) return null;

        var row = await conn.QuerySingleOrDefaultAsync<ChallengeRow>(new CommandDefinition(
            _sqlGetChallenge, new { Token = challengeToken }, cancellationToken: ct))
            .ConfigureAwait(false);
        return row is null ? null : new MfaChallengeSubject(row.Subject, (int)row.Scope);
    }

    private sealed class ChallengeRow
    {
        public string Subject { get; set; } = "";
        public long Scope { get; set; }
    }
}
