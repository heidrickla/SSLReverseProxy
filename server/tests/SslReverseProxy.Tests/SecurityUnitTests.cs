using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Security;
using Xunit;

namespace SslReverseProxy.Tests;

public class ApiKeyHasherTests
{
    [Fact]
    public void Verify_Succeeds_ForCorrectSecret()
    {
        var hasher = new ApiKeyHasher();
        var (hash, salt, iters) = hasher.Hash("s3cr3t-token");
        Assert.True(hasher.Verify("s3cr3t-token", hash, salt, iters));
    }

    [Fact]
    public void Verify_Fails_ForWrongSecret()
    {
        var hasher = new ApiKeyHasher();
        var (hash, salt, iters) = hasher.Hash("correct");
        Assert.False(hasher.Verify("wrong", hash, salt, iters));
    }

    [Fact]
    public void Hash_IsSaltedPerCall()
    {
        var hasher = new ApiKeyHasher();
        var a = hasher.Hash("same");
        var b = hasher.Hash("same");
        Assert.False(a.salt.AsSpan().SequenceEqual(b.salt));
        Assert.False(a.hash.AsSpan().SequenceEqual(b.hash));
    }

    [Fact]
    public void Pepper_ChangesTheHash()
    {
        var noPepper = new ApiKeyHasher();
        var (hash, salt, iters) = noPepper.Hash("token");
        var withPepper = new ApiKeyHasher(Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }));
        // A hasher with a different pepper must not verify the same secret/hash.
        Assert.False(withPepper.Verify("token", hash, salt, iters));
    }
}

public class PermissionsTests
{
    [Fact]
    public void Viewer_CannotControlProxyOrWrite()
    {
        Assert.False(Permissions.Has(Role.Viewer, Permission.ProxyControl));
        Assert.False(Permissions.Has(Role.Viewer, Permission.ServerWrite));
        Assert.False(Permissions.Has(Role.Viewer, Permission.UserWrite));
        Assert.True(Permissions.Has(Role.Viewer, Permission.ServerRead));
    }

    [Fact]
    public void Editor_CanControlProxyButNotManageUsers()
    {
        Assert.True(Permissions.Has(Role.Editor, Permission.ProxyControl));
        Assert.True(Permissions.Has(Role.Editor, Permission.RuleWrite));
        Assert.False(Permissions.Has(Role.Editor, Permission.UserWrite));
        Assert.False(Permissions.Has(Role.Editor, Permission.ApiKeyManage));
    }

    [Fact]
    public void Admin_HasEveryPermission()
    {
        foreach (var p in Enum.GetValues<Permission>())
            Assert.True(Permissions.Has(Role.Admin, p), p.ToString());
    }
}
