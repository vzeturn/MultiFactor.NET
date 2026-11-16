using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MM.Auth;

public static class MfaServiceCollectionExtensions
{
    /// <summary>
    /// Registers the validated <see cref="MfaOptions"/> and <see cref="IMfaFactorService"/>, and
    /// nothing else.
    /// </summary>
    /// <remarks>
    /// Deliberately registers no <see cref="IMfaRepository"/>, <see cref="ISecretProtector"/>,
    /// <see cref="IMfaKeyProvider"/> or <see cref="IMfaFactor"/> default — unlike MM.Mfa's AddMmMfa,
    /// which quietly wired SQLite and DPAPI. The core package depends on neither, so it has no
    /// honest default to offer. A host must also call <c>AddMmAuthSqlite</c> (or its own
    /// repository), <c>AddMmAuthAesProtector</c> (or its own protector) and register at least one
    /// factor; missing any of them fails at <c>BuildServiceProvider</c>, i.e. at startup.
    /// </remarks>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="configure">
    /// Receives a seed <see cref="MfaOptions"/> and returns the configured one, e.g.
    /// <c>o =&gt; o with { Issuer = "MyApp", ProtectionContext = "...", TablePrefix = "app_" }</c>.
    /// </param>
    public static IServiceCollection AddMmAuth(
        this IServiceCollection services, Func<MfaOptions, MfaOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var seed = new MfaOptions { Issuer = "MM", ProtectionContext = "MM.Auth", TablePrefix = "" };
        var options = configure(seed).Validate();

        services.TryAddSingleton(options);
        services.TryAddScoped<IMfaFactorService, MfaFactorService>();
        return services;
    }
}
