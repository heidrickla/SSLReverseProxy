using System.Net;
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

    private static ProxyTargetValidator Resolving(ProxyTargetPolicy policy, params string[] addresses) =>
        new(policy, _ => addresses.Length == 0 ? null : addresses.Select(IPAddress.Parse).ToList());

    private static readonly ProxyTargetPolicy NoLoopback = new() { AllowLoopback = false };

    [Theory]
    [InlineData("http://localhost:2019")]
    [InlineData("http://LOCALHOST.:8080")]
    [InlineData("http://admin.localhost:2019")]
    public void LoopbackNames_AreRefusedWhenPolicyDisallows_WhateverTheResolverSays(string url)
    {
        Assert.False(Resolving(NoLoopback).ValidateUpstream(url).Ok, url);
        Assert.False(Resolving(NoLoopback, "203.0.113.10").ValidateUpstream(url).Ok, url);
    }

    [Theory]
    [InlineData("http://127.1:2019")]
    [InlineData("http://2130706433:2019")]
    [InlineData("http://0x7f000001:2019")]
    [InlineData("http://0.0.0.0:2019")]
    [InlineData("http://[::]:2019")]
    [InlineData("http://[::1]:2019")]
    [InlineData("http://[::ffff:127.0.0.1]:2019")]
    public void LoopbackAddressForms_AreRefusedWhenPolicyDisallows(string url) =>
        Assert.False(Resolving(NoLoopback).ValidateUpstream(url).Ok, url);

    [Fact]
    public void ANameResolvingToLoopback_IsRefusedWhenPolicyDisallows()
    {
        var check = Resolving(NoLoopback, "127.0.0.1").ValidateUpstream("http://rebind.example.com:2019");
        Assert.False(check.Ok);
        Assert.Contains("127.0.0.1", check.Reason);
    }

    [Theory]
    [InlineData("169.254.169.254")]
    [InlineData("fd00:ec2::254")]
    [InlineData("fe80::1")]
    public void ANameResolvingToMetadata_IsRefusedUnderTheDefaultPolicy(string address) =>
        Assert.False(Resolving(new ProxyTargetPolicy(), address).ValidateUpstream("http://meta.example.com").Ok, address);

    [Fact]
    public void ANameResolvingToAPrivateAddress_IsRefusedWhenPolicyDisallows() =>
        Assert.False(Resolving(new ProxyTargetPolicy { AllowPrivateNetworks = false }, "10.1.2.3")
            .ValidateUpstream("https://internal.example.com").Ok);

    [Fact]
    public void EveryResolvedAddressIsChecked_NotOnlyTheFirst() =>
        Assert.False(Resolving(NoLoopback, "203.0.113.10", "127.0.0.1").ValidateUpstream("http://two.example.com").Ok);

    [Fact]
    public void ANameResolvingToAllowedAddresses_IsAccepted() =>
        Assert.True(Resolving(NoLoopback, "203.0.113.10", "10.0.0.5").ValidateUpstream("http://app.example.com:8080").Ok);

    [Fact]
    public void ANameThatDoesNotResolve_IsAccepted() =>
        Assert.True(Resolving(NoLoopback).ValidateUpstream("http://authelia:9091").Ok);

    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("::1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("10.0.0.5", true)]
    [InlineData("203.0.113.10", true)]
    public void CheckAddress_AppliesThePolicyToOneAddress(string address, bool ok) =>
        Assert.Equal(ok, new ProxyTargetValidator(NoLoopback).CheckAddress(IPAddress.Parse(address)).Ok);

    [Theory]
    [InlineData("example.com", true)]
    [InlineData("sub.example.co.uk", true)]
    [InlineData("has space.com", false)]
    [InlineData("", false)]
    public void DomainValidation(string domain, bool expected) =>
        Assert.Equal(expected, _default.ValidateDomain(domain).Ok);
}
