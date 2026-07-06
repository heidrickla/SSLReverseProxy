using SslReverseProxy.Core.Security;
using Xunit;

namespace SslReverseProxy.Tests;

public class ProxyTargetValidatorTests
{
    private readonly ProxyTargetValidator _default = new();

    [Theory]
    [InlineData("http://10.0.0.10:8080")]
    [InlineData("https://api.internal:8443")]
    [InlineData("http://localhost:3000")]
    [InlineData("http://192.168.1.10")]
    public void ValidUpstreams_AreAccepted(string url) =>
        Assert.True(_default.ValidateUpstream(url).Ok, url);

    [Theory]
    [InlineData("http://169.254.169.254/latest/meta-data/")] // AWS metadata
    [InlineData("http://metadata.google.internal")]           // GCP metadata
    [InlineData("file:///etc/passwd")]
    [InlineData("javascript:alert(1)")]
    [InlineData("ftp://example.com")]
    [InlineData("not-a-url")]
    [InlineData("")]
    public void DangerousOrMalformedUpstreams_AreRejected(string url) =>
        Assert.False(_default.ValidateUpstream(url).Ok, url);

    [Fact]
    public void Loopback_RejectedWhenPolicyDisallows()
    {
        var strict = new ProxyTargetValidator(new ProxyTargetPolicy { AllowLoopback = false });
        Assert.False(strict.ValidateUpstream("http://127.0.0.1:9000").Ok);
    }

    [Fact]
    public void PrivateNetwork_RejectedWhenPolicyDisallows()
    {
        var strict = new ProxyTargetValidator(new ProxyTargetPolicy { AllowPrivateNetworks = false });
        Assert.False(strict.ValidateUpstream("http://10.1.2.3:8080").Ok);
    }

    [Theory]
    [InlineData("example.com", true)]
    [InlineData("sub.example.co.uk", true)]
    [InlineData("has space.com", false)]
    [InlineData("", false)]
    public void DomainValidation(string domain, bool expected) =>
        Assert.Equal(expected, _default.ValidateDomain(domain).Ok);
}
