using System.Data.Common;

namespace MM.Auth.Sqlite;

/// <summary>
/// DDL for the three MFA tables. Every statement is IF NOT EXISTS, so running it against an
/// already-provisioned database is a no-op and no migration is involved.
/// </summary>
/// <remarks>
/// No column carries a database-side time default: MM.Mfa used <c>strftime('now')</c>, which meant
/// the schema only worked on SQLite. Here the adapter computes every timestamp in C# and binds it,
/// so a Postgres or SQL Server adapter can reuse the same repository logic with only its own DDL.
/// <c>AUTOINCREMENT</c> on the backup-code id stays, because this file is the SQLite-specific part
/// — another adapter substitutes IDENTITY or SERIAL in its own schema.
/// </remarks>
public static class SqliteMfaSchema
{
    public static string GetDdl(string tablePrefix)
    {
        ArgumentNullException.ThrowIfNull(tablePrefix);
        return
            "CREATE TABLE IF NOT EXISTS " + tablePrefix + "mfa_secret (" +
            "initial TEXT NOT NULL, factor_kind TEXT NOT NULL, secret_encrypted BLOB NOT NULL, " +
            "enrolled_at TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, " +
            "PRIMARY KEY (initial, factor_kind)); " +
            "CREATE TABLE IF NOT EXISTS " + tablePrefix + "mfa_backup_code (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, initial TEXT NOT NULL, code_hash TEXT NOT NULL, " +
            "used_at TEXT NULL, created_at TEXT NOT NULL); " +
            "CREATE INDEX IF NOT EXISTS ix_" + tablePrefix + "mfa_backup_code_initial ON " +
            tablePrefix + "mfa_backup_code (initial); " +
            "CREATE TABLE IF NOT EXISTS " + tablePrefix + "mfa_challenge (" +
            "challenge_token TEXT PRIMARY KEY, initial TEXT NOT NULL, rvc INTEGER NOT NULL, " +
            "created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT NULL); " +
            "CREATE INDEX IF NOT EXISTS ix_" + tablePrefix + "mfa_challenge_expiry ON " +
            tablePrefix + "mfa_challenge (expires_at);";
    }

    public static async Task EnsureAsync(
        DbConnection conn, MfaOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conn);
        ArgumentNullException.ThrowIfNull(options);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = GetDdl(options.TablePrefix);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}
