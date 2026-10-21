using System.Text.RegularExpressions;

namespace SslReverseProxy.Core.Domain;

/// <summary>
/// The identity providers a rule can sign requests in through, each as Caddy's <c>forward_auth</c>
/// expansion would call it: the verify path, the identity headers copied onto the request, the path
/// prefix its sign-in flow needs proxied on the protected host, and where a 401 sends the browser.
/// </summary>
public static partial class SignInProviders
{
    public const string Authelia = "authelia";
    public const string Authentik = "authentik";
    public const string OAuth2Proxy = "oauth2-proxy";
    public const string CloudflareAccess = "cloudflare-access";

    /// <summary>The control plane's verify path for a Cloudflare Access rule; the rule id follows.</summary>
    public const string CloudflareVerifyPath = "/api/sign-in/cloudflare/";

    /// <summary>The header Cloudflare puts the Access token in.</summary>
    public const string CloudflareTokenHeader = "Cf-Access-Jwt-Assertion";

    /// <summary>The header the verified email reaches the upstream in.</summary>
    public const string CloudflareEmailHeader = "Cf-Access-Authenticated-User-Email";

    public sealed record Profile(
        string Name, string Label, string VerifyUri, IReadOnlyList<string> CopyHeaders, string? CallbackPrefix, string? SignInOn401);

    public static readonly IReadOnlyDictionary<string, Profile> Profiles = new Dictionary<string, Profile>(StringComparer.Ordinal)
    {
        [Authelia] = new(Authelia, "Authelia", "/api/authz/forward-auth",
            ["Remote-Email", "Remote-Groups", "Remote-Name", "Remote-User"], null, null),
        [Authentik] = new(Authentik, "Authentik", "/outpost.goauthentik.io/auth/caddy",
            ["X-Authentik-Email", "X-Authentik-Entitlements", "X-Authentik-Groups", "X-Authentik-Jwt", "X-Authentik-Meta-App",
             "X-Authentik-Meta-Jwks", "X-Authentik-Meta-Outpost", "X-Authentik-Meta-Provider", "X-Authentik-Meta-Version",
             "X-Authentik-Name", "X-Authentik-Uid", "X-Authentik-Username"],
            "/outpost.goauthentik.io", null),
        [OAuth2Proxy] = new(OAuth2Proxy, "oauth2-proxy", "/oauth2/auth",
            ["X-Auth-Request-Email", "X-Auth-Request-Groups", "X-Auth-Request-Preferred-Username", "X-Auth-Request-User"],
            "/oauth2", "/oauth2/sign_in?rd={http.request.scheme}://{http.request.host}{http.request.uri}"),
        [CloudflareAccess] = new(CloudflareAccess, "Cloudflare Access", CloudflareVerifyPath,
            [CloudflareEmailHeader], null, null),
    };

    /// <summary>
    /// Every provider's identity headers. A sign-in rule deletes them all from the client's request before the
    /// verify call, the callback proxy and the upstream, so only the rule's own provider can set one.
    /// </summary>
    public static readonly IReadOnlyList<string> IdentityHeaders =
        [.. Profiles.Values.SelectMany(p => p.CopyHeaders).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal)];

    /// <summary>Providers Caddy calls at the rule's verifier address; Cloudflare Access is checked by the control plane.</summary>
    public static bool UsesVerifier(string? provider) => provider is Authelia or Authentik or OAuth2Proxy;

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.cloudflareaccess\\.com$")]
    public static partial Regex TeamDomain();

    [GeneratedRegex("^[0-9a-f]{64}$")]
    public static partial Regex Audience();
}
