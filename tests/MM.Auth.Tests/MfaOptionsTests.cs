namespace MM.Auth.Tests;

public class MfaOptionsTests
{
    private static MfaOptions Valid() => new()
    {
        Issuer = "MyApp",
        ProtectionContext = "MyApp.Auth",
        TablePrefix = "app_",
    };

    [Fact]
    public void A_valid_option_set_validates_and_returns_itself()
    {
        var options = Valid();

        options.Validate().Should().BeSameAs(options);
    }

    [Fact]
    public void Defaults_are_ten_backup_codes_five_minute_challenge_ten_minute_pending()
    {
        var options = Valid();

        options.BackupCodeCount.Should().Be(10);
        options.ChallengeLifetime.Should().Be(TimeSpan.FromMinutes(5));
        options.PendingEnrollLifetime.Should().Be(TimeSpan.FromMinutes(10));
    }

    [Fact]
    public void An_empty_table_prefix_is_allowed() =>
        (Valid() with { TablePrefix = "" }).Validate().TablePrefix.Should().BeEmpty();

    [Theory]
    [InlineData("bad-prefix")]
    [InlineData("App_")]
    [InlineData("1app_")]
    [InlineData("app ")]
    public void An_unsafe_table_prefix_throws(string prefix) =>
        Assert.Throws<ArgumentException>(() => (Valid() with { TablePrefix = prefix }).Validate());

    [Fact]
    public void A_blank_issuer_throws() =>
        Assert.Throws<ArgumentException>(() => (Valid() with { Issuer = " " }).Validate());

    [Fact]
    public void A_blank_protection_context_throws() =>
        Assert.Throws<ArgumentException>(() => (Valid() with { ProtectionContext = " " }).Validate());

    [Theory]
    [InlineData(0)]
    [InlineData(101)]
    public void A_backup_code_count_outside_one_to_hundred_throws(int count) =>
        Assert.Throws<ArgumentException>(() => (Valid() with { BackupCodeCount = count }).Validate());

    [Fact]
    public void A_zero_lifetime_throws() =>
        Assert.Throws<ArgumentException>(
            () => (Valid() with { ChallengeLifetime = TimeSpan.Zero }).Validate());

    [Fact]
    public void Table_names_are_the_prefix_plus_mfa_plus_suffix() =>
        Valid().Table("secret").Should().Be("app_mfa_secret");
}
