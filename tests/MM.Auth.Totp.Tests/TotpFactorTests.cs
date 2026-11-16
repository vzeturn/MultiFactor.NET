using System.Text;
using OtpNet;

namespace MM.Auth.Totp.Tests;

public class TotpFactorTests
{
    private static readonly MfaOptions Options = new MfaOptions
    {
        Issuer = "MyApp",
        ProtectionContext = "MyApp.Auth",
        TablePrefix = "app_",
    }.Validate();

    private readonly TotpFactor _factor = new(Options);

    private async Task<byte[]> NewSecretAsync() =>
        (await _factor.StartEnrollAsync("AB", CancellationToken.None)).PlaintextSecret;

    [Fact]
    public void The_kind_is_totp() => _factor.Kind.Should().Be("totp");

    [Fact]
    public async Task A_generated_secret_is_twenty_bytes_and_never_repeats()
    {
        var first = await NewSecretAsync();
        var second = await NewSecretAsync();

        first.Should().HaveCount(20);
        first.Should().NotEqual(second);
    }

    [Fact]
    public async Task Start_enroll_reports_the_totp_kind_and_the_display_data()
    {
        var start = await _factor.StartEnrollAsync("AB", CancellationToken.None);

        start.Kind.Should().Be("totp");
        start.Data["secret"].Should().Be(Base32Encoding.ToString(start.PlaintextSecret));
        start.Data["otpAuthUri"].Should().Contain("secret=" + start.Data["secret"]);
    }

    [Fact]
    public async Task The_otpauth_uri_carries_the_issuer_the_label_and_the_base32_secret()
    {
        var start = await _factor.StartEnrollAsync("AB", CancellationToken.None);

        var uri = start.Data["otpAuthUri"];

        uri.Should().StartWith("otpauth://totp/");
        uri.Should().Contain("issuer=MyApp");
        uri.Should().Contain("secret=" + Base32Encoding.ToString(start.PlaintextSecret));
        uri.Should().Contain("digits=6");
        uri.Should().Contain("period=30");
    }

    [Fact]
    public async Task The_current_code_verifies()
    {
        var secret = await NewSecretAsync();
        var code = new OtpNet.Totp(secret).ComputeTotp();

        (await _factor.VerifyAsync(secret, new FactorProof.Code(code), CancellationToken.None))
            .Should().BeTrue();
    }

    [Fact]
    public async Task A_code_one_step_in_the_past_still_verifies()
    {
        var secret = await NewSecretAsync();
        var code = new OtpNet.Totp(secret).ComputeTotp(DateTime.UtcNow.AddSeconds(-30));

        (await _factor.VerifyAsync(secret, new FactorProof.Code(code), CancellationToken.None))
            .Should().BeTrue();
    }

    [Fact]
    public async Task A_code_one_step_in_the_future_still_verifies()
    {
        var secret = await NewSecretAsync();
        var code = new OtpNet.Totp(secret).ComputeTotp(DateTime.UtcNow.AddSeconds(30));

        (await _factor.VerifyAsync(secret, new FactorProof.Code(code), CancellationToken.None))
            .Should().BeTrue();
    }

    [Fact]
    public async Task A_code_three_steps_away_does_not_verify()
    {
        var secret = await NewSecretAsync();
        var code = new OtpNet.Totp(secret).ComputeTotp(DateTime.UtcNow.AddSeconds(90));

        (await _factor.VerifyAsync(secret, new FactorProof.Code(code), CancellationToken.None))
            .Should().BeFalse();
    }

    /// <remarks>
    /// RFC 6238 Appendix B vector: the ASCII secret "12345678901234567890" at T = 59s
    /// (counter 1) yields 287082 for SHA-1 / 6 digits / 30s.
    /// </remarks>
    [Fact]
    public void The_rfc_6238_reference_vector_matches()
    {
        var secret = Encoding.ASCII.GetBytes("12345678901234567890");
        var at = DateTimeOffset.FromUnixTimeSeconds(59).UtcDateTime;

        var code = new OtpNet.Totp(secret, step: 30, mode: OtpHashMode.Sha1, totpSize: 6).ComputeTotp(at);

        code.Should().Be("287082");
    }

    [Fact]
    public async Task A_wrong_code_does_not_verify() =>
        (await _factor.VerifyAsync(await NewSecretAsync(), new FactorProof.Code("000000"), CancellationToken.None))
            .Should().BeFalse();

    [Fact]
    public async Task A_blank_code_does_not_verify() =>
        (await _factor.VerifyAsync(await NewSecretAsync(), new FactorProof.Code("  "), CancellationToken.None))
            .Should().BeFalse();

    [Fact]
    public async Task A_code_from_another_secret_does_not_verify()
    {
        var code = new OtpNet.Totp(await NewSecretAsync()).ComputeTotp();

        (await _factor.VerifyAsync(await NewSecretAsync(), new FactorProof.Code(code), CancellationToken.None))
            .Should().BeFalse();
    }

    [Fact]
    public async Task An_assertion_proof_does_not_verify() =>
        (await _factor.VerifyAsync(await NewSecretAsync(), new FactorProof.Assertion([1, 2, 3]), CancellationToken.None))
            .Should().BeFalse();
}
