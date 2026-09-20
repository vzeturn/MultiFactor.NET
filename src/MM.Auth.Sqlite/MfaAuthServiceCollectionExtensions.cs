using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MM.Auth.Sqlite;

public static class MfaAuthServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="SqliteMfaRepository"/> as the <see cref="IMfaRepository"/>. The host
    /// must already have registered an <see cref="IMfaConnectionFactory"/> and called
    /// AddMmAuth (which supplies <see cref="MfaOptions"/>).
    /// </summary>
    public static IServiceCollection AddMmAuthSqlite(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IMfaRepository, SqliteMfaRepository>();
        return services;
    }
}
