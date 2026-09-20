namespace MM.Auth;

/// <summary>
/// Supplies 256-bit keys. The library never generates, stores, or rotates a key itself — the
/// host owns key material and its lifecycle entirely.
/// </summary>
public interface IMfaKeyProvider
{
    /// <summary>The key new ciphertext is sealed with. Must be exactly 32 bytes.</summary>
    ValueTask<ReadOnlyMemory<byte>> GetCurrentKeyAsync(CancellationToken ct = default);

    /// <summary>
    /// Resolves a key by the id recorded in an existing blob, so data sealed before a rotation
    /// still opens. Returns null once the host has retired that key.
    /// </summary>
    ValueTask<ReadOnlyMemory<byte>?> GetKeyAsync(string keyId, CancellationToken ct = default);

    /// <summary>Id of the key <see cref="GetCurrentKeyAsync"/> returns. Must be 1..255 UTF-8 bytes.</summary>
    string CurrentKeyId { get; }
}
