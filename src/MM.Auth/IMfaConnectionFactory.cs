using System.Data.Common;

namespace MM.Auth;

/// <summary>
/// The database connection source owned by the host. This library ships no driver: the host
/// already owns the connection string, pooling and pragmas, and this is the one seam it fills.
/// </summary>
public interface IMfaConnectionFactory
{
    Task<DbConnection> CreateOpenAsync(CancellationToken ct = default);
}
