namespace MM.Auth;

/// <summary>
/// Outcome of confirming an enrollment. End-user mistakes are values, not exceptions.
/// </summary>
public abstract record FactorEnrollResult
{
    private FactorEnrollResult() { }

    /// <summary>The pending token is older than the configured pending-enroll lifetime.</summary>
    public sealed record Expired : FactorEnrollResult;

    /// <summary>
    /// The proof did not verify, or the token was malformed/tampered with. Those two are
    /// deliberately indistinguishable to the caller: telling them apart tells an attacker
    /// whether a forged token was structurally accepted.
    /// </summary>
    public sealed record InvalidProof : FactorEnrollResult;

    public sealed record Success(IReadOnlyList<string> BackupCodes) : FactorEnrollResult;
}
