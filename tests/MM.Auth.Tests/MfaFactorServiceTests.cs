using System.Text;
using Microsoft.Extensions.DependencyInjection;

namespace MM.Auth.Tests;

public class MfaFactorServiceTests
{
    private const string TotpSecret = "totp-secret";
    private const string OtherSecret = "other-secret";

    private static MfaOptions Options() => new MfaOptions
    {
        Issuer = "MM.PdaOrder",
        ProtectionContext = "MM.PdaOrder.Auth",
        TablePrefix = "pda_",
    }.Validate();

    private readonly FakeRepository _repo = new();
    private readonly FakeProtector _protector = new();
    private readonly FakeFactor _totp = new("totp", TotpSecret);
    private readonly FakeFactor _other = new("other", OtherSecret);
    private readonly MfaFactorService _svc;

    public MfaFactorServiceTests() => _svc = NewService(Options());

    private MfaFactorService NewService(MfaOptions options) =>
        new([_totp, _other], _repo, _protector, options);

    private async Task<IReadOnlyList<string>> EnrollAsync(
        string subject, string kind = "totp", string secret = TotpSecret)
    {
        var start = await _svc.StartEnrollAsync(subject, kind);
        var result = Assert.IsType<FactorEnrollResult.Success>(
            await _svc.ConfirmEnrollAsync(start.PendingToken, new FactorProof.Code(secret)));
        return result.BackupCodes;
    }

    [Fact]
    public async Task Start_enroll_persists_nothing_and_returns_the_factor_display_data()
    {
        var start = await _svc.StartEnrollAsync("AB", "totp");

        start.Kind.Should().Be("totp");
        start.PendingToken.Should().NotBeNullOrWhiteSpace();
        start.Data["subject"].Should().Be("AB");
        (await _svc.IsEnabledAsync("AB", "totp")).Should().BeFalse();
    }

    [Fact]
    public async Task Start_enroll_for_an_unregistered_factor_kind_throws()
    {
        var act = () => _svc.StartEnrollAsync("AB", "webauthn");

        await Assert.ThrowsAsync<InvalidOperationException>(act);
    }

    [Fact]
    public async Task A_pending_token_is_base64url_with_no_padding()
    {
        var start = await _svc.StartEnrollAsync("AB", "totp");

        start.PendingToken.Should().NotContain("+").And.NotContain("/").And.NotContain("=");
    }

    [Fact]
    public async Task Peek_pending_subject_returns_the_subject_the_token_was_issued_to()
    {
        var start = await _svc.StartEnrollAsync("ADM", "totp");

        _svc.PeekPendingSubject(start.PendingToken).Should().Be("ADM");
    }

    [Fact]
    public void Peek_pending_subject_returns_null_for_a_token_that_is_not_one_of_ours() =>
        _svc.PeekPendingSubject("not-a-token").Should().BeNull();

    [Fact]
    public async Task Peek_pending_subject_returns_null_for_an_expired_token()
    {
        var svc = NewService(Options() with { PendingEnrollLifetime = TimeSpan.FromSeconds(-1) });
        var start = await svc.StartEnrollAsync("AB", "totp");

        svc.PeekPendingSubject(start.PendingToken).Should().BeNull();
    }

    [Fact]
    public async Task Confirm_enroll_persists_nothing_when_the_proof_is_wrong()
    {
        var start = await _svc.StartEnrollAsync("AB", "totp");

        Assert.IsType<FactorEnrollResult.InvalidProof>(
            await _svc.ConfirmEnrollAsync(start.PendingToken, new FactorProof.Code("wrong")));
        (await _svc.IsEnabledAsync("AB", "totp")).Should().BeFalse();
    }

    [Fact]
    public async Task Confirm_enroll_with_the_right_proof_enables_and_returns_backup_codes()
    {
        var codes = await EnrollAsync("AB");

        codes.Should().HaveCount(10);
        codes.Should().OnlyHaveUniqueItems();
        codes.Should().OnlyContain(c => c.Length == 8 && c.All(char.IsAsciiDigit));
        (await _svc.IsEnabledAsync("AB", "totp")).Should().BeTrue();
        (await _svc.CountRemainingBackupCodesAsync("AB")).Should().Be(10);
    }

    [Fact]
    public async Task Backup_code_count_follows_the_option()
    {
        var svc = NewService(Options() with { BackupCodeCount = 3 });
        var start = await svc.StartEnrollAsync("AB", "totp");

        var result = Assert.IsType<FactorEnrollResult.Success>(
            await svc.ConfirmEnrollAsync(start.PendingToken, new FactorProof.Code(TotpSecret)));

        result.BackupCodes.Should().HaveCount(3);
    }

    [Fact]
    public async Task An_expired_pending_token_reports_Expired_not_InvalidProof()
    {
        var svc = NewService(Options() with { PendingEnrollLifetime = TimeSpan.FromSeconds(-1) });
        var start = await svc.StartEnrollAsync("AB", "totp");

        Assert.IsType<FactorEnrollResult.Expired>(
            await svc.ConfirmEnrollAsync(start.PendingToken, new FactorProof.Code(TotpSecret)));
    }

    [Fact]
    public async Task A_garbage_pending_token_reports_InvalidProof() =>
        Assert.IsType<FactorEnrollResult.InvalidProof>(
            await _svc.ConfirmEnrollAsync("not-a-token", new FactorProof.Code(TotpSecret)));

    [Fact]
    public async Task The_stored_secret_is_sealed_under_the_secret_context_not_the_pending_one()
    {
        await EnrollAsync("AB");

        var stored = await _repo.GetSecretAsync("AB", "totp");

        stored.Should().NotBeNull();
        stored.Should().NotEqual(Encoding.UTF8.GetBytes(TotpSecret));
        (await _protector.UnprotectAsync(stored!, "MM.PdaOrder.Auth|secret"))
            .Should().Equal(Encoding.UTF8.GetBytes(TotpSecret));
    }

    [Fact]
    public async Task Verify_accepts_a_proof_the_enrolled_factor_accepts()
    {
        await EnrollAsync("AB");

        (await _svc.VerifyAsync("AB", new FactorProof.Code(TotpSecret))).Should().BeTrue();
    }

    [Fact]
    public async Task Verify_falls_back_to_a_backup_code_and_consumes_it()
    {
        var codes = await EnrollAsync("AB");

        (await _svc.VerifyAsync("AB", new FactorProof.Code(codes[0]))).Should().BeTrue();
        (await _svc.VerifyAsync("AB", new FactorProof.Code(codes[0]))).Should().BeFalse();
        (await _svc.CountRemainingBackupCodesAsync("AB")).Should().Be(9);
    }

    [Fact]
    public async Task Verify_rejects_an_unknown_subject() =>
        (await _svc.VerifyAsync("ZZ", new FactorProof.Code("000000"))).Should().BeFalse();

    [Fact]
    public async Task Verify_does_not_fall_back_to_backup_codes_for_an_assertion_proof()
    {
        await EnrollAsync("AB");

        (await _svc.VerifyAsync("AB", new FactorProof.Assertion([1, 2, 3]))).Should().BeFalse();
    }

    [Fact]
    public async Task Verify_does_not_consult_a_factor_the_subject_has_not_enabled()
    {
        await EnrollAsync("AB");
        var before = _other.VerifyCallCount;

        await _svc.VerifyAsync("AB", new FactorProof.Code(TotpSecret));

        _other.VerifyCallCount.Should().Be(before);
    }

    [Fact]
    public async Task Two_factors_for_one_subject_do_not_interfere()
    {
        await EnrollAsync("AB");
        await EnrollAsync("AB", "other", OtherSecret);

        (await _svc.IsEnabledAsync("AB", "totp")).Should().BeTrue();
        (await _svc.IsEnabledAsync("AB", "other")).Should().BeTrue();
        (await _svc.VerifyAsync("AB", new FactorProof.Code(OtherSecret))).Should().BeTrue();
    }

    [Fact]
    public async Task Disable_turns_one_factor_off_and_leaves_the_other_alone()
    {
        await EnrollAsync("AB");
        await EnrollAsync("AB", "other", OtherSecret);

        await _svc.DisableAsync("AB", "other");

        (await _svc.IsEnabledAsync("AB", "totp")).Should().BeTrue();
        (await _svc.IsEnabledAsync("AB", "other")).Should().BeFalse();
    }

    [Fact]
    public async Task A_challenge_reports_its_lifetime_and_consumes_once()
    {
        var challenge = await _svc.CreateChallengeAsync("AB", 7);

        challenge.ExpiresInSeconds.Should().Be(300);
        (await _svc.ConsumeChallengeAsync(challenge.Token)).Should().Be(new MfaChallengeSubject("AB", 7));
        (await _svc.ConsumeChallengeAsync(challenge.Token)).Should().BeNull();
    }

    [Fact]
    public async Task An_unknown_challenge_token_consumes_to_null() =>
        (await _svc.ConsumeChallengeAsync("deadbeef")).Should().BeNull();

    [Fact]
    public void AddMmAuth_throws_at_registration_for_an_invalid_table_prefix() =>
        Assert.Throws<ArgumentException>(() => new ServiceCollection().AddMmAuth(o => o with
        {
            Issuer = "x",
            ProtectionContext = "x",
            TablePrefix = "bad-prefix",
        }));

    [Fact]
    public void AddMmAuth_resolves_IMfaFactorService_once_the_host_supplies_the_seams()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IMfaRepository>(_repo);
        services.AddSingleton<ISecretProtector>(_protector);
        services.AddSingleton<IMfaFactor>(_totp);
        services.AddMmAuth(o => o with
        {
            Issuer = "MM.PdaOrder",
            ProtectionContext = "MM.PdaOrder.Auth",
            TablePrefix = "pda_",
        });

        using var provider = services.BuildServiceProvider(validateScopes: true);
        using var scope = provider.CreateScope();

        scope.ServiceProvider.GetRequiredService<IMfaFactorService>()
            .Should().BeOfType<MfaFactorService>();
    }

    [Fact]
    public void AddMmAuth_registers_no_repository_protector_or_factor()
    {
        var services = new ServiceCollection();
        services.AddMmAuth(o => o with
        {
            Issuer = "MM.PdaOrder",
            ProtectionContext = "MM.PdaOrder.Auth",
            TablePrefix = "pda_",
        });

        services.Should().NotContain(d => d.ServiceType == typeof(IMfaRepository));
        services.Should().NotContain(d => d.ServiceType == typeof(ISecretProtector));
        services.Should().NotContain(d => d.ServiceType == typeof(IMfaKeyProvider));
        services.Should().NotContain(d => d.ServiceType == typeof(IMfaFactor));
    }
}
