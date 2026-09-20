using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;

namespace MM.Auth.Crypto.Aes.Tests;

/// <summary>
/// An in-memory key provider. A real host would resolve these from a secret manager; nothing about
/// the protector's contract changes.
/// </summary>
public sealed class FakeKeyProvider : IMfaKeyProvider
{
    private readonly Dictionary<string, byte[]> _keys = [];

    public FakeKeyProvider(string currentKeyId = "k1")
    {
        CurrentKeyId = currentKeyId;
        _keys[currentKeyId] = RandomNumberGenerator.GetBytes(32);
    }

    public string CurrentKeyId { get; private set; }

    /// <summary>Adds a new current key while keeping the old one resolvable, i.e. a rotation.</summary>
    public void Rotate(string newKeyId)
    {
        _keys[newKeyId] = RandomNumberGenerator.GetBytes(32);
        CurrentKeyId = newKeyId;
    }

    /// <summary>Retires a key the way a host would after its retention window closes.</summary>
    public void Retire(string keyId) => _keys.Remove(keyId);

    public ValueTask<ReadOnlyMemory<byte>> GetCurrentKeyAsync(CancellationToken ct = default) =>
        ValueTask.FromResult<ReadOnlyMemory<byte>>(_keys[CurrentKeyId]);

    public ValueTask<ReadOnlyMemory<byte>?> GetKeyAsync(string keyId, CancellationToken ct = default) =>
        ValueTask.FromResult<ReadOnlyMemory<byte>?>(
            _keys.TryGetValue(keyId, out var key) ? key : (ReadOnlyMemory<byte>?)null);
}

public class AesGcmSecretProtectorTests
{
    private const int VersionByteIndex = 0;
    private static readonly byte[] Plaintext = Encoding.UTF8.GetBytes("a-totp-secret-value");

    private readonly FakeKeyProvider _keys = new();
    private readonly AesGcmSecretProtector _protector;

    public AesGcmSecretProtectorTests() => _protector = new AesGcmSecretProtector(_keys);

    [Fact]
    public async Task A_sealed_secret_round_trips()
    {
        var blob = await _protector.ProtectAsync(Plaintext, "secret");

        (await _protector.UnprotectAsync(blob, "secret")).Should().Equal(Plaintext);
    }

    [Fact]
    public async Task The_blob_is_not_the_plaintext()
    {
        var blob = await _protector.ProtectAsync(Plaintext, "secret");

        blob.Should().NotEqual(Plaintext);
    }

    [Fact]
    public async Task The_blob_layout_is_version_keyid_nonce_ciphertext_tag()
    {
        var blob = await _protector.ProtectAsync(Plaintext, "secret");

        var keyIdLength = blob[1];
        blob[VersionByteIndex].Should().Be(1);
        Encoding.UTF8.GetString(blob, 2, keyIdLength).Should().Be("k1");
        blob.Should().HaveCount(1 + 1 + keyIdLength + 12 + Plaintext.Length + 16);
    }

    [Fact]
    public async Task Two_seals_of_the_same_plaintext_differ_because_the_nonce_is_fresh()
    {
        var first = await _protector.ProtectAsync(Plaintext, "secret");
        var second = await _protector.ProtectAsync(Plaintext, "secret");

        first.Should().NotEqual(second);
    }

    [Fact]
    public async Task A_blob_sealed_under_pending_does_not_open_under_secret()
    {
        var blob = await _protector.ProtectAsync(Plaintext, "pending");

        await Assert.ThrowsAnyAsync<CryptographicException>(
            async () => await _protector.UnprotectAsync(blob, "secret"));
    }

    [Fact]
    public async Task A_tampered_ciphertext_does_not_open()
    {
        var blob = await _protector.ProtectAsync(Plaintext, "secret");
        blob[^1] ^= 0xFF;

        await Assert.ThrowsAnyAsync<CryptographicException>(
            async () => await _protector.UnprotectAsync(blob, "secret"));
    }

    [Fact]
    public async Task A_blob_sealed_before_a_rotation_still_opens_afterwards()
    {
        var blob = await _protector.ProtectAsync(Plaintext, "secret");

        _keys.Rotate("k2");

        (await _protector.UnprotectAsync(blob, "secret")).Should().Equal(Plaintext);
    }

    [Fact]
    public async Task After_a_rotation_new_blobs_carry_the_new_key_id()
    {
        _keys.Rotate("k2");

        var blob = await _protector.ProtectAsync(Plaintext, "secret");

        Encoding.UTF8.GetString(blob, 2, blob[1]).Should().Be("k2");
    }

    [Fact]
    public async Task A_retired_key_id_raises_SecretProtectionException()
    {
        var blob = await _protector.ProtectAsync(Plaintext, "secret");
        _keys.Rotate("k2");
        _keys.Retire("k1");

        var ex = await Assert.ThrowsAsync<SecretProtectionException>(
            async () => await _protector.UnprotectAsync(blob, "secret"));

        ex.Message.Should().Be("Key 'k1' is not available.");
    }

    [Fact]
    public async Task An_unrecognised_format_version_raises_SecretProtectionException()
    {
        var blob = await _protector.ProtectAsync(Plaintext, "secret");
        blob[VersionByteIndex] = 9;

        var ex = await Assert.ThrowsAsync<SecretProtectionException>(
            async () => await _protector.UnprotectAsync(blob, "secret"));

        ex.Message.Should().Be("Unrecognized ciphertext format version 9.");
    }

    [Fact]
    public async Task A_truncated_blob_raises_SecretProtectionException()
    {
        var blob = await _protector.ProtectAsync(Plaintext, "secret");

        await Assert.ThrowsAsync<SecretProtectionException>(
            async () => await _protector.UnprotectAsync(blob[..4], "secret"));
    }

    [Fact]
    public async Task An_empty_blob_raises_SecretProtectionException() =>
        await Assert.ThrowsAsync<SecretProtectionException>(
            async () => await _protector.UnprotectAsync([], "secret"));

    [Fact]
    public async Task A_key_that_is_not_256_bits_raises_SecretProtectionException()
    {
        var protector = new AesGcmSecretProtector(new ShortKeyProvider());

        await Assert.ThrowsAsync<SecretProtectionException>(
            async () => await protector.ProtectAsync(Plaintext, "secret"));
    }

    [Fact]
    public void AddMmAuthAesProtector_registers_the_protector_and_the_key_provider()
    {
        var services = new ServiceCollection();

        services.AddMmAuthAesProtector(_keys);

        using var provider = services.BuildServiceProvider(validateScopes: true);
        provider.GetRequiredService<ISecretProtector>().Should().BeOfType<AesGcmSecretProtector>();
        provider.GetRequiredService<IMfaKeyProvider>().Should().BeSameAs(_keys);
    }

    private sealed class ShortKeyProvider : IMfaKeyProvider
    {
        public string CurrentKeyId => "short";

        public ValueTask<ReadOnlyMemory<byte>> GetCurrentKeyAsync(CancellationToken ct = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>>(new byte[16]);

        public ValueTask<ReadOnlyMemory<byte>?> GetKeyAsync(string keyId, CancellationToken ct = default) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>?>(new byte[16]);
    }
}
