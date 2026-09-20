using System.Security.Cryptography;
using System.Text;

namespace MM.Auth.Crypto.Aes;

/// <summary>
/// AES-256-GCM secret protection, the cross-platform replacement for MM.Mfa's Windows DPAPI.
/// </summary>
/// <remarks>
/// <para>The blob is self-describing so a key rotation never requires a schema change:</para>
/// <code>
/// [1 byte ] format version, currently 1
/// [1 byte ] keyId length N
/// [N bytes] keyId, UTF-8
/// [12     ] nonce, fresh per Protect call
/// [len(pt)] ciphertext
/// [16     ] GCM tag
/// </code>
/// <para>The <c>context</c> argument is bound as GCM associated data, so a blob sealed for one
/// purpose cannot be replayed into another.</para>
/// </remarks>
public sealed class AesGcmSecretProtector(IMfaKeyProvider keyProvider) : ISecretProtector
{
    private const byte FormatVersion = 1;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private const int HeaderPrefixSize = 2; // version byte + keyId length byte

    /// <inheritdoc />
    public async ValueTask<byte[]> ProtectAsync(
        byte[] plaintext, string context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentException.ThrowIfNullOrWhiteSpace(context);

        var keyId = keyProvider.CurrentKeyId;
        var keyIdBytes = Encoding.UTF8.GetBytes(keyId);
        if (keyIdBytes.Length is 0 or > 255)
            throw new SecretProtectionException(
                "IMfaKeyProvider.CurrentKeyId must be 1..255 UTF-8 bytes; got " +
                keyIdBytes.Length + ".");

        var key = await keyProvider.GetCurrentKeyAsync(ct).ConfigureAwait(false);
        if (key.Length != KeySize)
            throw new SecretProtectionException(
                "IMfaKeyProvider returned a " + key.Length * 8 + "-bit key; AES-256-GCM needs 256 bits.");

        var blob = new byte[HeaderPrefixSize + keyIdBytes.Length + NonceSize + plaintext.Length + TagSize];
        blob[0] = FormatVersion;
        blob[1] = (byte)keyIdBytes.Length;
        keyIdBytes.CopyTo(blob, HeaderPrefixSize);

        var nonceOffset = HeaderPrefixSize + keyIdBytes.Length;
        var nonce = blob.AsSpan(nonceOffset, NonceSize);
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = blob.AsSpan(nonceOffset + NonceSize, plaintext.Length);
        var tag = blob.AsSpan(nonceOffset + NonceSize + plaintext.Length, TagSize);

        using var aes = new AesGcm(key.Span, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(context));
        return blob;
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> UnprotectAsync(
        byte[] ciphertext, string context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentException.ThrowIfNullOrWhiteSpace(context);

        if (ciphertext.Length < HeaderPrefixSize)
            throw new SecretProtectionException("Ciphertext blob is too short to carry a header.");

        var version = ciphertext[0];
        if (version != FormatVersion)
            throw new SecretProtectionException(
                "Unrecognized ciphertext format version " + version + ".");

        var keyIdLength = ciphertext[1];
        var minimum = HeaderPrefixSize + keyIdLength + NonceSize + TagSize;
        if (keyIdLength == 0 || ciphertext.Length < minimum)
            throw new SecretProtectionException("Ciphertext blob is truncated.");

        var keyId = Encoding.UTF8.GetString(ciphertext, HeaderPrefixSize, keyIdLength);
        var key = await keyProvider.GetKeyAsync(keyId, ct).ConfigureAwait(false)
            ?? throw new SecretProtectionException("Key '" + keyId + "' is not available.");
        if (key.Length != KeySize)
            throw new SecretProtectionException(
                "IMfaKeyProvider returned a " + key.Length * 8 +
                "-bit key for '" + keyId + "'; AES-256-GCM needs 256 bits.");

        var nonceOffset = HeaderPrefixSize + keyIdLength;
        var payloadLength = ciphertext.Length - minimum;
        var nonce = ciphertext.AsSpan(nonceOffset, NonceSize);
        var payload = ciphertext.AsSpan(nonceOffset + NonceSize, payloadLength);
        var tag = ciphertext.AsSpan(nonceOffset + NonceSize + payloadLength, TagSize);

        var plaintext = new byte[payloadLength];
        using var aes = new AesGcm(key.Span, TagSize);
        // A wrong context or tampered blob throws AuthenticationTagMismatchException from here.
        // That is left to propagate unwrapped on purpose: it means "this data is not what it
        // claims", which is categorically different from the key-management faults above.
        aes.Decrypt(nonce, payload, tag, plaintext, Encoding.UTF8.GetBytes(context));
        return plaintext;
    }
}
