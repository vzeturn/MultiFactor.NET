namespace MM.Auth;

/// <summary>
/// Seals and opens secrets at rest. Pluggable so a host can back it with a KMS or key vault
/// without forking the library.
/// </summary>
/// <remarks>
/// Async-first: <see cref="IMfaKeyProvider"/> is async, and the rest of the library is async, so
/// forcing crypto to be synchronous would only reintroduce sync-over-async bridging at every
/// call site.
/// </remarks>
public interface ISecretProtector
{
    /// <param name="plaintext">The secret data to seal.</param>
    /// <param name="context">
    /// Purpose label bound into the ciphertext as authenticated data. A blob sealed under
    /// <c>"pending"</c> must not open under <c>"secret"</c>.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    ValueTask<byte[]> ProtectAsync(byte[] plaintext, string context, CancellationToken ct = default);

    /// <param name="ciphertext">The sealed data to open.</param>
    /// <param name="context">
    /// Purpose label that must match the context used when sealing. A blob sealed under
    /// <c>"pending"</c> must not open under <c>"secret"</c>.
    /// </param>
    /// <param name="ct">Cancellation token.</param>
    ValueTask<byte[]> UnprotectAsync(byte[] ciphertext, string context, CancellationToken ct = default);
}
