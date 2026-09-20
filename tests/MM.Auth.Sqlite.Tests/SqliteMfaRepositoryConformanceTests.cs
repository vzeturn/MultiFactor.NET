using MM.Auth.Testing;

namespace MM.Auth.Sqlite.Tests;

/// <summary>
/// The SQLite adapter against the shared behavioural contract. There are no SQLite-specific
/// assertions here on purpose: anything true only of SQLite belongs in SqliteMfaSchemaTests.
/// </summary>
public sealed class SqliteMfaRepositoryConformanceTests : MfaRepositoryConformanceTests, IDisposable
{
    private static MfaOptions Options() => new MfaOptions
    {
        Issuer = "MM.PdaOrder",
        ProtectionContext = "MM.PdaOrder.Auth",
        TablePrefix = "pda_",
    }.Validate();

    private readonly List<TestDb> _dbs = [];

    private IMfaRepository Build(MfaOptions options)
    {
        var db = new TestDb(options);
        _dbs.Add(db);
        return new SqliteMfaRepository(db, options);
    }

    protected override IMfaRepository CreateRepository() => Build(Options());

    protected override IMfaRepository CreateRepositoryWithExpiredChallenges() =>
        Build(Options() with { ChallengeLifetime = TimeSpan.FromSeconds(-1) });

    public void Dispose()
    {
        foreach (var db in _dbs) db.Dispose();
    }
}
