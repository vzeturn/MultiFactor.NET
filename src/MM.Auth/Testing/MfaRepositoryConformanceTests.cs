using System.Security.Cryptography;
using Xunit;
using AwesomeAssertions;

namespace MM.Auth.Testing;

/// <summary>
/// The behavioural contract every <see cref="IMfaRepository"/> adapter must satisfy, written
/// against the interface and never against a particular engine. Ships inside the MM.Auth package
/// so an adapter author inherits the whole suite instead of reinventing the cases.
/// </summary>
/// <remarks>
/// Secrets here are opaque bytes: the repository stores ciphertext produced elsewhere, so these
/// tests deliberately never involve an <see cref="ISecretProtector"/>.
/// </remarks>
public abstract class MfaRepositoryConformanceTests
{
    /// <summary>A repository over a database that is empty and private to this test.</summary>
    protected abstract IMfaRepository CreateRepository();

    /// <summary>
    /// A repository configured so that every challenge it creates is already expired. Override when
    /// the adapter's challenge lifetime is configurable; the default skips the expiry assertion by
    /// returning the ordinary repository, which would make that one test vacuous — so any adapter
    /// that can express a negative lifetime should override it.
    /// </summary>
    protected virtual IMfaRepository CreateRepositoryWithExpiredChallenges() => CreateRepository();

    private static byte[] NewSecret() => RandomNumberGenerator.GetBytes(20);

    [Fact]
    public async Task An_unknown_subject_is_not_enabled_and_has_no_secret()
    {
        var repo = CreateRepository();

        (await repo.IsEnabledAsync("ZZ", "totp")).Should().BeFalse();
        (await repo.GetSecretAsync("ZZ", "totp")).Should().BeNull();
    }

    [Fact]
    public async Task Enroll_stores_the_ciphertext_verbatim_and_the_backup_codes()
    {
        var repo = CreateRepository();
        var secret = NewSecret();

        await repo.EnrollAsync("AB", "totp", secret, ["11111111", "22222222"]);

        (await repo.IsEnabledAsync("AB", "totp")).Should().BeTrue();
        (await repo.GetSecretAsync("AB", "totp")).Should().Equal(secret);
        (await repo.CountRemainingBackupCodesAsync("AB")).Should().Be(2);
    }

    [Fact]
    public async Task A_second_factor_for_the_same_subject_does_not_evict_the_first()
    {
        var repo = CreateRepository();
        var totpSecret = NewSecret();
        var otherSecret = NewSecret();

        await repo.EnrollAsync("AB", "totp", totpSecret, ["11111111"]);
        await repo.EnrollAsync("AB", "other", otherSecret, ["22222222"]);

        (await repo.GetSecretAsync("AB", "totp")).Should().Equal(totpSecret);
        (await repo.GetSecretAsync("AB", "other")).Should().Equal(otherSecret);
    }

    [Fact]
    public async Task Re_enrolling_a_factor_replaces_its_secret_and_the_backup_codes()
    {
        var repo = CreateRepository();
        await repo.EnrollAsync("AB", "totp", NewSecret(), ["11111111", "22222222"]);
        var second = NewSecret();

        await repo.EnrollAsync("AB", "totp", second, ["33333333"]);

        (await repo.GetSecretAsync("AB", "totp")).Should().Equal(second);
        (await repo.CountRemainingBackupCodesAsync("AB")).Should().Be(1);
        (await repo.TryConsumeBackupCodeAsync("AB", "11111111")).Should().BeFalse();
    }

    [Fact]
    public async Task Disable_removes_only_the_named_factor()
    {
        var repo = CreateRepository();
        var totpSecret = NewSecret();
        await repo.EnrollAsync("AB", "totp", totpSecret, ["11111111"]);
        await repo.EnrollAsync("AB", "other", NewSecret(), ["22222222"]);

        await repo.DisableAsync("AB", "other");

        (await repo.IsEnabledAsync("AB", "other")).Should().BeFalse();
        (await repo.GetSecretAsync("AB", "other")).Should().BeNull();
        (await repo.IsEnabledAsync("AB", "totp")).Should().BeTrue();
        (await repo.GetSecretAsync("AB", "totp")).Should().Equal(totpSecret);
    }

    [Fact]
    public async Task Disable_clears_the_backup_codes()
    {
        var repo = CreateRepository();
        await repo.EnrollAsync("AB", "totp", NewSecret(), ["11111111"]);

        await repo.DisableAsync("AB", "totp");

        (await repo.CountRemainingBackupCodesAsync("AB")).Should().Be(0);
    }

    [Fact]
    public async Task A_backup_code_can_be_consumed_exactly_once()
    {
        var repo = CreateRepository();
        await repo.EnrollAsync("AB", "totp", NewSecret(), ["11111111", "22222222"]);

        (await repo.TryConsumeBackupCodeAsync("AB", "11111111")).Should().BeTrue();
        (await repo.TryConsumeBackupCodeAsync("AB", "11111111")).Should().BeFalse();
        (await repo.CountRemainingBackupCodesAsync("AB")).Should().Be(1);
    }

    [Fact]
    public async Task An_unknown_backup_code_is_rejected()
    {
        var repo = CreateRepository();
        await repo.EnrollAsync("AB", "totp", NewSecret(), ["11111111"]);

        (await repo.TryConsumeBackupCodeAsync("AB", "99999999")).Should().BeFalse();
    }

    [Fact]
    public async Task A_backup_code_does_not_work_for_another_subject()
    {
        var repo = CreateRepository();
        await repo.EnrollAsync("AB", "totp", NewSecret(), ["11111111"]);

        (await repo.TryConsumeBackupCodeAsync("CD", "11111111")).Should().BeFalse();
    }

    [Fact]
    public async Task A_challenge_round_trips_its_subject_and_scope()
    {
        var repo = CreateRepository();

        var token = await repo.CreateChallengeAsync("AB", 7);

        (await repo.TryConsumeChallengeAsync(token)).Should().Be(new MfaChallengeSubject("AB", 7));
    }

    [Fact]
    public async Task A_challenge_can_be_consumed_exactly_once()
    {
        var repo = CreateRepository();
        var token = await repo.CreateChallengeAsync("AB", 1);

        (await repo.TryConsumeChallengeAsync(token)).Should().NotBeNull();
        (await repo.TryConsumeChallengeAsync(token)).Should().BeNull();
    }

    [Fact]
    public async Task An_unknown_challenge_token_consumes_to_null() =>
        (await CreateRepository().TryConsumeChallengeAsync("deadbeef")).Should().BeNull();

    [Fact]
    public async Task An_expired_challenge_cannot_be_consumed()
    {
        var repo = CreateRepositoryWithExpiredChallenges();

        var token = await repo.CreateChallengeAsync("AB", 1);

        (await repo.TryConsumeChallengeAsync(token)).Should().BeNull();
    }
}
