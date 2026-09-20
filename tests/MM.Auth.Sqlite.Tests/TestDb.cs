using System.Data.Common;
using Microsoft.Data.Sqlite;

namespace MM.Auth.Sqlite.Tests;

/// <summary>
/// A private in-memory SQLite database per instance. The keep-alive connection matters: a
/// shared-cache in-memory database is destroyed the moment its last connection closes, so without
/// it every <see cref="CreateOpenAsync"/> would see a fresh empty schema.
/// </summary>
public sealed class TestDb : IMfaConnectionFactory, IDisposable
{
    private readonly string _connectionString;
    private readonly SqliteConnection _keepAlive;

    public TestDb(MfaOptions options)
    {
        _connectionString =
            "Data Source=mmauth-" + Guid.NewGuid().ToString("N") + ";Mode=Memory;Cache=Shared";
        _keepAlive = new SqliteConnection(_connectionString);
        _keepAlive.Open();
        SqliteMfaSchema.EnsureAsync(_keepAlive, options).GetAwaiter().GetResult();
    }

    public async Task<DbConnection> CreateOpenAsync(CancellationToken ct = default)
    {
        var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct);
        return conn;
    }

    public void Dispose() => _keepAlive.Dispose();
}
