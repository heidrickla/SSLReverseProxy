using System.Text.Json.Nodes;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// Builds a Caddy JSON config from the rule set. Caddy owns ACME / automatic
/// HTTPS, so certificate issuance and renewal are handled by a mature, audited
/// implementation rather than hand-rolled here.
/// </summary>
public static class CaddyConfigBuilder
{
    public static JsonObject Build(IReadOnlyCollection<ProxyRule> rules, ProxyOptions options)
    {
        var routes = new JsonArray();

        foreach (var rule in rules.Where(r => r.Enabled))
        {
            var handle = new JsonArray();

            // Per-route access control (evaluated before proxying). Deny wins.
            foreach (var acl in BuildAccessControlHandlers(rule))
                handle.Add(acl);

            // Rate limit (caddy-ratelimit plugin) — requires the plugin in the build.
            if (rule.RateLimitPerMinute is > 0)
                handle.Add(BuildRateLimitHandler(rule.RateLimitPerMinute.Value));

            // HTTP basic auth (native Caddy) using the stored bcrypt hash.
            if (!string.IsNullOrEmpty(rule.BasicAuthUsername) && !string.IsNullOrEmpty(rule.BasicAuthPasswordHash))
                handle.Add(BuildBasicAuthHandler(rule.BasicAuthUsername!, rule.BasicAuthPasswordHash!));

            handle.Add(new JsonObject
            {
                ["handler"] = "reverse_proxy",
                ["upstreams"] = new JsonArray
                {
                    new JsonObject { ["dial"] = ToDial(rule.UpstreamUrl) },
                },
            });

            routes.Add(new JsonObject
            {
                ["match"] = new JsonArray { new JsonObject { ["host"] = new JsonArray { rule.Domain } } },
                ["handle"] = handle,
                ["terminal"] = true,
            });
        }

        var servers = new JsonObject
        {
            ["srv0"] = new JsonObject
            {
                ["listen"] = new JsonArray { ":443", ":80" },
                ["routes"] = routes,
                // Enable Prometheus metrics collection for this server.
                ["metrics"] = new JsonObject(),
            },
        };

        var apps = new JsonObject
        {
            ["http"] = new JsonObject { ["servers"] = servers },
        };

        if (!string.IsNullOrWhiteSpace(options.AcmeContactEmail))
        {
            apps["tls"] = new JsonObject
            {
                ["automation"] = new JsonObject
                {
                    ["policies"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["issuers"] = new JsonArray
                            {
                                new JsonObject
                                {
                                    ["module"] = "acme",
                                    ["email"] = options.AcmeContactEmail,
                                    ["ca"] = options.UseAcmeStaging
                                        ? "https://acme-staging-v02.api.letsencrypt.org/directory"
                                        : "https://acme-v02.api.letsencrypt.org/directory",
                                },
                            },
                        },
                    },
                },
            };
        }

        // Admin API pinned to loopback — never exposed off-box.
        return new JsonObject
        {
            ["admin"] = new JsonObject { ["listen"] = LoopbackAdmin(options.AdminEndpoint) },
            ["apps"] = apps,
        };
    }

    // Native Caddy remote_ip access control. Denied ranges get an immediate 403;
    // if an allow-list is set, anything outside it gets a 403.
    private static IEnumerable<JsonObject> BuildAccessControlHandlers(ProxyRule rule)
    {
        var denied = ParseCidrs(rule.DeniedCidrs);
        var allowed = ParseCidrs(rule.AllowedCidrs);

        if (denied.Count > 0)
        {
            yield return Forbidden(new JsonObject
            {
                ["remote_ip"] = new JsonObject { ["ranges"] = ToJsonArray(denied) },
            });
        }

        if (allowed.Count > 0)
        {
            yield return Forbidden(new JsonObject
            {
                ["not"] = new JsonArray
                {
                    new JsonObject { ["remote_ip"] = new JsonObject { ["ranges"] = ToJsonArray(allowed) } },
                },
            });
        }
    }

    // A terminal subroute that responds 403 when the given matcher matches.
    private static JsonObject Forbidden(JsonObject matcher) => new()
    {
        ["handler"] = "subroute",
        ["routes"] = new JsonArray
        {
            new JsonObject
            {
                ["match"] = new JsonArray { matcher },
                ["handle"] = new JsonArray
                {
                    new JsonObject { ["handler"] = "static_response", ["status_code"] = 403 },
                },
            },
        },
    };

    // caddy-ratelimit plugin handler: N events per minute, keyed by client IP.
    private static JsonObject BuildRateLimitHandler(int perMinute) => new()
    {
        ["handler"] = "rate_limit",
        ["rate_limit"] = new JsonObject
        {
            ["zones"] = new JsonObject
            {
                ["per_route"] = new JsonObject
                {
                    ["key"] = "{http.request.remote_host}",
                    ["events"] = perMinute,
                    ["window"] = "1m",
                },
            },
        },
    };

    // Native Caddy basic_auth handler using a bcrypt-hashed password.
    private static JsonObject BuildBasicAuthHandler(string username, string bcryptHash) => new()
    {
        ["handler"] = "authentication",
        ["providers"] = new JsonObject
        {
            ["http_basic"] = new JsonObject
            {
                ["accounts"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["username"] = username,
                        ["password"] = bcryptHash,
                    },
                },
                ["hash"] = new JsonObject { ["algorithm"] = "bcrypt" },
            },
        },
    };

    private static List<string> ParseCidrs(string? csv) =>
        string.IsNullOrWhiteSpace(csv)
            ? new List<string>()
            : csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    private static JsonArray ToJsonArray(IEnumerable<string> items)
    {
        var arr = new JsonArray();
        foreach (var i in items) arr.Add(i);
        return arr;
    }

    // Caddy "dial" is host:port. Derive port from scheme when not explicit.
    private static string ToDial(string upstreamUrl)
    {
        var uri = new Uri(upstreamUrl, UriKind.Absolute);
        var port = uri.IsDefaultPort
            ? (uri.Scheme == Uri.UriSchemeHttps ? 443 : 80)
            : uri.Port;
        return $"{uri.Host}:{port}";
    }

    private static string LoopbackAdmin(string adminEndpoint)
    {
        var uri = new Uri(adminEndpoint, UriKind.Absolute);
        return $"{uri.Host}:{uri.Port}";
    }
}
