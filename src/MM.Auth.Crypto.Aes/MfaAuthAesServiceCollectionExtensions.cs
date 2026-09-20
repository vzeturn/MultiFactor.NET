using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MM.Auth.Crypto.Aes;

/// <summary>
/// Dependency-injection registration helpers for the AES-256-GCM <see cref="ISecretProtector"/>.
/// </summary>
public static class MfaAuthAesServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="AesGcmSecretProtector"/> as the <see cref="ISecretProtector"/>, backed by
    /// the host's key provider. Call alongside <c>AddMmAuth</c>.
    /// </summary>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="keyProvider">The host-supplied key provider backing the protector.</param>
    /// <returns>The same <see cref="IServiceCollection"/>, for chaining.</returns>
    public static IServiceCollection AddMmAuthAesProtector(
        this IServiceCollection services, IMfaKeyProvider keyProvider)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(keyProvider);

        services.TryAddSingleton(keyProvider);
        services.TryAddSingleton<ISecretProtector, AesGcmSecretProtector>();
        return services;
    }
}
