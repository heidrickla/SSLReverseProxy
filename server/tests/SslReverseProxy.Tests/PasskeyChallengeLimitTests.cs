using SslReverseProxy.Api.Auth;
using Xunit;
using Kind = SslReverseProxy.Api.Auth.PasskeyChallenges.Kind;

namespace SslReverseProxy.Tests;

public class PasskeyChallengeLimitTests
{
    private readonly ManualClock _clock = new(DateTimeOffset.UtcNow);

    private string Add(PasskeyChallenges store, Kind kind, Guid? user, string json)
    {
        var handle = store.Add(kind, user, json);
        _clock.Advance(TimeSpan.FromMilliseconds(1));
        return handle;
    }

    [Fact]
    public void ASignInFlood_DoesNotCrowdOutARegistration()
    {
        var store = new PasskeyChallenges(_clock);
        var user = Guid.NewGuid();
        var registration = Add(store, Kind.Register, user, "register");
        for (var i = 0; i < PasskeyChallenges.SignInCapacity + 50; i++) Add(store, Kind.SignIn, null, $"s{i}");

        Assert.Equal("register", store.Take(registration, Kind.Register, user));
    }

    [Fact]
    public void ASignInPastTheLimit_IsStored_AndTheOldestSignInIsDropped()
    {
        var store = new PasskeyChallenges(_clock);
        var oldest = Add(store, Kind.SignIn, null, "oldest");
        var second = Add(store, Kind.SignIn, null, "second");
        for (var i = 2; i < PasskeyChallenges.SignInCapacity; i++) Add(store, Kind.SignIn, null, $"s{i}");
        var newest = Add(store, Kind.SignIn, null, "newest");

        Assert.Equal("newest", store.Take(newest, Kind.SignIn, null));
        Assert.Null(store.Take(oldest, Kind.SignIn, null));
        Assert.Equal("second", store.Take(second, Kind.SignIn, null));
    }

    [Fact]
    public void ARegistrationFlood_DoesNotCrowdOutASignIn()
    {
        var store = new PasskeyChallenges(_clock);
        var signIn = Add(store, Kind.SignIn, null, "sign-in");
        var user = Guid.NewGuid();
        for (var i = 0; i < PasskeyChallenges.RegisterCapacity + 10; i++) Add(store, Kind.Register, user, $"r{i}");

        Assert.Equal("sign-in", store.Take(signIn, Kind.SignIn, null));
    }
}
