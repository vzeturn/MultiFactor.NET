using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace MM.Auth.Sqlite.Tests;

public class SqliteMfaSchemaTests
{
    private static MfaOptions Options(string prefix = "app_") => new MfaOptions
    {
        Issuer = "MyApp",
        ProtectionContext = "MyApp.Auth",
        TablePrefix = prefix,
    }.Validate();

    [Fact]
    public void The_ddl_names_all_three_tables_with_the_prefix()
    {
        var ddl = SqliteMfaSchema.GetDdl("app_");

        ddl.Should().Contain("app_mfa_secret");
        ddl.Should().Contain("app_mfa_backup_code");
        ddl.Should().Contain("app_mfa_challenge");
    }

    [Fact]
    public void The_ddl_uses_no_database_specific_time_functions()
    {
        var ddl = SqliteMfaSchema.GetDdl("app_");

        ddl.Should().NotContain("strftime");
        ddl.Should().NotContain("datetime(");
    }

    [Fact]
    public void The_secret_table_is_keyed_by_subject_and_factor_kind()
    {
        var ddl = SqliteMfaSchema.GetDdl("app_");

        ddl.Should().Contain("PRIMARY KEY (initial, factor_kind)");
    }

    [Fact]
    public async Task Ensure_creates_the_three_tables()
    {
        await using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();

        await SqliteMfaSchema.EnsureAsync(conn, Options());

        var names = (await conn.QueryAsync<string>(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")).ToList();

        names.Should().Contain("app_mfa_secret");
        names.Should().Contain("app_mfa_backup_code");
        names.Should().Contain("app_mfa_challenge");
    }

    [Fact]
    public async Task Ensure_is_idempotent()
    {
        await using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();

        await SqliteMfaSchema.EnsureAsync(conn, Options());
        await SqliteMfaSchema.EnsureAsync(conn, Options());

        (await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'app_mfa_secret'"))
            .Should().Be(1);
    }

    [Fact]
    public async Task An_unprefixed_schema_is_also_valid()
    {
        await using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();

        await SqliteMfaSchema.EnsureAsync(conn, Options(""));

        (await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'mfa_secret'"))
            .Should().Be(1);
    }

    [Fact]
    public void AddMmAuthSqlite_registers_the_repository()
    {
        var options = Options();
        using var db = new TestDb(options);
        var services = new ServiceCollection();
        services.AddSingleton(options);
        services.AddSingleton<IMfaConnectionFactory>(db);

        services.AddMmAuthSqlite();

        using var provider = services.BuildServiceProvider(validateScopes: true);
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<IMfaRepository>()
            .Should().BeOfType<SqliteMfaRepository>();
    }
}
