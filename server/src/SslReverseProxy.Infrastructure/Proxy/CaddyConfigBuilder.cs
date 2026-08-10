using System.Text.Json.Nodes;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// Builds a Caddy JSON config from the rule set. Caddy owns ACME / automatic
/// HTTPS, so certificate issuance and renewal are handled by a mature, audited
/// implementation rather than hand-rolled here.
/// <para>
/// Key names here are load-bearing. Caddy decodes every module config with
/// DisallowUnknownFields, so a misspelled key fails the whole config load —
/// every site, not just the rule that carried it. Values are the opposite:
/// several are looked up in a map with no miss check, so a wrong <em>value</em>
/// loads cleanly and quietly does nothing. Both failure modes are why the tests
/// assert on exact keys, and why /api/proxy/validate runs `caddy validate`
/// before anything reaches the live proxy.
/// </para>
/// </summary>
public static class CaddyConfigBuilder
{
    // Caddy's duration fields accept a Go duration string as well as an integer
    // count of nanoseconds. Strings keep the emitted config readable.
    private const string AccessLogName = "access";
    private const string AccessLoggerId = "http.log.access." + AccessLogName;

    public static JsonObject Build(IReadOnlyCollection<ProxyRule> rules, ProxyOptions options)
    {
        var active = rules.Where(r => r.Enabled).ToList();
        var routes = new JsonArray();

        foreach (var rule in active)
        {
            var handle = new JsonArray();

            // Headers first, and deferred, so they are stamped on whatever the
            // route ends up returning. Placed after the access handlers they
            // would cover only proxied responses — the 403, 429, 413 and 401
            // this route generates itself would go out bare, which is precisely
            // when a browser is most likely to be looking at an error page.
            if (BuildSecurityHeadersHandler(rule) is { } headers)
                handle.Add(headers);

            // Per-route access control (evaluated before proxying). Deny wins.
            foreach (var acl in BuildAccessControlHandlers(rule))
                handle.Add(acl);

            // Rate limit (caddy-ratelimit plugin) — requires the plugin in the build.
            if (rule.RateLimitPerMinute is > 0)
                handle.Add(BuildRateLimitHandler(rule.RateLimitPerMinute.Value));

            // Body cap before auth, so an oversized upload is bounded at the
            // cheapest point rather than after credentials are checked.
            if (rule.MaxRequestBodyBytes is > 0)
                handle.Add(new JsonObject
                {
                    ["handler"] = "request_body",
                    ["max_size"] = rule.MaxRequestBodyBytes.Value,
                });

            // HTTP basic auth (native Caddy) using the stored bcrypt hash.
            if (!string.IsNullOrEmpty(rule.BasicAuthUsername) && !string.IsNullOrEmpty(rule.BasicAuthPasswordHash))
                handle.Add(BuildBasicAuthHandler(rule.BasicAuthUsername!, rule.BasicAuthPasswordHash!));

            handle.Add(BuildReverseProxyHandler(rule));

            routes.Add(new JsonObject
            {
                ["match"] = new JsonArray { new JsonObject { ["host"] = new JsonArray { rule.Domain } } },
                ["handle"] = handle,
                ["terminal"] = true,
            });
        }

        var srv0 = new JsonObject
        {
            ["listen"] = new JsonArray { ":443", ":80" },
            ["routes"] = routes,
            // Enable Prometheus metrics collection for this server.
            ["metrics"] = new JsonObject(),
        };

        // Believe X-Forwarded-For only from the proxies we were told about, so
        // the per-rule IP lists match on the real client. With no trust list
        // configured, Caddy ignores the header entirely and client_ip is just
        // the peer address — which is the correct default for a proxy that
        // faces clients directly, and unspoofable.
        var trusted = ParseCsv(options.TrustedProxyCidrs).Where(IsIpOrCidr).ToList();
        if (trusted.Count > 0)
        {
            srv0["trusted_proxies"] = new JsonObject
            {
                ["source"] = "static",
                ["ranges"] = ToJsonArray(trusted),
            };
            // Strict parsing walks X-Forwarded-For right to left and stops at
            // the first hop that is not trusted. Without it Caddy takes the
            // leftmost entry, which the client wrote and can therefore forge —
            // and forging it is exactly how you would walk through an allow-list.
            srv0["trusted_proxies_strict"] = 1;
        }

        AddIfPositive(srv0, "read_timeout", options.ReadTimeoutSeconds);
        AddIfPositive(srv0, "read_header_timeout", options.ReadHeaderTimeoutSeconds);
        AddIfPositive(srv0, "write_timeout", options.WriteTimeoutSeconds);
        AddIfPositive(srv0, "idle_timeout", options.IdleTimeoutSeconds);

        // Only when something is actually served over TLS. A connection policy
        // is what turns :443 into a TLS listener, so emitting one for a config
        // whose hosts are all plaintext (or for the empty bootstrap config)
        // would stand up a TLS port with nothing behind it.
        //
        // A single policy with no "match" is a catch-all, so it applies to every
        // connection while leaving SNI-based certificate selection alone. If
        // every policy carried a match, a handshake matching none would die
        // before any certificate was chosen.
        if (active.Any(r => r.EnableTls))
        {
            var policy = new JsonObject { ["protocol_min"] = NormalizeTlsVersion(options.TlsMinVersion) };
            var ciphers = ParseCsv(options.TlsCipherSuites);
            if (ciphers.Count > 0) policy["cipher_suites"] = ToJsonArray(ciphers);
            srv0["tls_connection_policies"] = new JsonArray { policy };
        }

        // Rules with TLS switched off are excluded from automatic HTTPS, which
        // otherwise issues a certificate and redirects :80 to :443 for every
        // host that appears in a route.
        var plaintextHosts = active.Where(r => !r.EnableTls).Select(r => r.Domain).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (plaintextHosts.Count > 0)
        {
            srv0["automatic_https"] = new JsonObject
            {
                ["skip"] = ToJsonArray(plaintextHosts),
            };
        }

        if (!string.IsNullOrWhiteSpace(options.AccessLogPath))
        {
            var logs = new JsonObject { ["default_logger_name"] = AccessLogName };
            var skip = active.Where(r => r.SkipAccessLog).Select(r => r.Domain)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (skip.Count > 0) logs["skip_hosts"] = ToJsonArray(skip);
            srv0["logs"] = logs;
        }

        var apps = new JsonObject
        {
            ["http"] = new JsonObject { ["servers"] = new JsonObject { ["srv0"] = srv0 } },
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
        var root = new JsonObject
        {
            ["admin"] = new JsonObject { ["listen"] = LoopbackAdmin(options.AdminEndpoint) },
            ["apps"] = apps,
        };

        if (BuildLogging(options) is { } logging)
            root["logging"] = logging;

        return root;
    }

    /// <summary>
    /// Routes the data-plane access log to its own file. The default logger is
    /// told to exclude it as well, otherwise every request is written twice:
    /// once to the access log and once to Caddy's own stderr log.
    /// </summary>
    private static JsonObject? BuildLogging(ProxyOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.AccessLogPath)) return null;

        return new JsonObject
        {
            ["logs"] = new JsonObject
            {
                [AccessLogName] = new JsonObject
                {
                    ["include"] = new JsonArray { AccessLoggerId },
                    ["writer"] = new JsonObject
                    {
                        ["output"] = "file",
                        ["filename"] = options.AccessLogPath,
                        ["roll_size_mb"] = Math.Max(1, options.AccessLogRollSizeMb),
                        ["roll_keep_days"] = Math.Max(1, options.AccessLogKeepDays),
                    },
                    ["encoder"] = new JsonObject { ["format"] = "json" },
                    ["level"] = "INFO",
                },
                ["default"] = new JsonObject
                {
                    ["exclude"] = new JsonArray { AccessLoggerId },
                },
            },
        };
    }

    private static JsonObject BuildReverseProxyHandler(ProxyRule rule)
    {
        var upstreams = rule.AllUpstreams();

        // De-duplicate on the dial address, not the URL. "http://10.0.0.5" and
        // "http://10.0.0.5:80" are different strings for the same backend, and
        // listing both would quietly give it two shares of the load.
        var dials = new JsonArray();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in upstreams)
        {
            var dial = ToDial(u);
            if (seen.Add(dial)) dials.Add(new JsonObject { ["dial"] = dial });
        }

        var proxy = new JsonObject
        {
            ["handler"] = "reverse_proxy",
            ["upstreams"] = dials,
        };

        // "dial" carries no scheme, so an https upstream reached without a TLS
        // transport would be spoken to in cleartext on port 443. The transport
        // is what actually selects HTTPS to the backend.
        var transport = new JsonObject();
        if (UsesTls(upstreams))
            transport["tls"] = new JsonObject();
        if (rule.DialTimeoutSeconds is > 0)
            transport["dial_timeout"] = Seconds(rule.DialTimeoutSeconds.Value);
        if (rule.UpstreamReadTimeoutSeconds is > 0)
            transport["read_timeout"] = Seconds(rule.UpstreamReadTimeoutSeconds.Value);
        if (rule.UpstreamWriteTimeoutSeconds is > 0)
            transport["write_timeout"] = Seconds(rule.UpstreamWriteTimeoutSeconds.Value);
        if (transport.Count > 0)
        {
            transport["protocol"] = "http";
            proxy["transport"] = transport;
        }

        if (dials.Count > 1)
        {
            proxy["load_balancing"] = new JsonObject
            {
                ["selection_policy"] = new JsonObject
                {
                    ["policy"] = string.IsNullOrWhiteSpace(rule.LoadBalancePolicy)
                        ? "round_robin"
                        : rule.LoadBalancePolicy!.ToLowerInvariant(),
                },
            };
        }

        if (!string.IsNullOrWhiteSpace(rule.HealthCheckPath))
        {
            var activeCheck = new JsonObject { ["uri"] = rule.HealthCheckPath };
            if (rule.HealthCheckIntervalSeconds is > 0)
                activeCheck["interval"] = Seconds(rule.HealthCheckIntervalSeconds.Value);
            if (rule.HealthCheckTimeoutSeconds is > 0)
                activeCheck["timeout"] = Seconds(rule.HealthCheckTimeoutSeconds.Value);
            // Only when the operator asked for one. A single digit means a
            // whole status class, so 2 is "any 2xx" — which is NARROWER than
            // Caddy's own default of 200-399, so defaulting to it here would
            // quietly mark a backend that redirects /health as down.
            if (rule.HealthCheckExpectStatus is { } expect)
                activeCheck["expect_status"] = expect;

            proxy["health_checks"] = new JsonObject { ["active"] = activeCheck };
        }

        return proxy;
    }

    /// <summary>
    /// Response headers that harden the route. Applied deferred so they are
    /// written at response time and win over anything the upstream sent,
    /// rather than being appended alongside it.
    /// </summary>
    private static JsonObject? BuildSecurityHeadersHandler(ProxyRule rule)
    {
        var set = new JsonObject();

        if (rule.EnableSecurityHeaders)
        {
            set["X-Content-Type-Options"] = new JsonArray { "nosniff" };
            set["Referrer-Policy"] = new JsonArray { "strict-origin-when-cross-origin" };
        }

        // HSTS only means anything over TLS, and promising it on a plaintext
        // route would tell browsers to refuse the only scheme it serves.
        // The route itself is shared by the :80 and :443 listeners, but a
        // TLS-enabled host has automatic HTTPS redirecting :80 to :443 ahead of
        // it, so the header is not in practice served over plaintext.
        if (rule.HstsMaxAgeDays is > 0 && rule.EnableTls)
        {
            var seconds = (long)rule.HstsMaxAgeDays.Value * 86400;
            var value = rule.HstsIncludeSubdomains
                ? $"max-age={seconds}; includeSubDomains"
                : $"max-age={seconds}";
            // One string, never a two-element array: Caddy comma-joins arrays,
            // and a comma here makes the whole policy unparseable, so browsers
            // discard it entirely rather than just ignoring the second half.
            set["Strict-Transport-Security"] = new JsonArray { value };
        }

        if (!string.IsNullOrWhiteSpace(rule.FrameOptions))
            set["X-Frame-Options"] = new JsonArray { rule.FrameOptions!.ToUpperInvariant() };

        if (set.Count == 0) return null;

        return new JsonObject
        {
            ["handler"] = "headers",
            ["response"] = new JsonObject
            {
                ["set"] = set,
                ["deferred"] = true,
            },
        };
    }

    // Native Caddy client_ip access control. Denied ranges get an immediate 403;
    // if an allow-list is set, anything outside it gets a 403.
    private static IEnumerable<JsonObject> BuildAccessControlHandlers(ProxyRule rule)
    {
        var denied = ParseCsv(rule.DeniedCidrs);
        var allowed = ParseCsv(rule.AllowedCidrs);

        if (denied.Count > 0)
        {
            yield return Forbidden(new JsonObject
            {
                ["client_ip"] = new JsonObject { ["ranges"] = ToJsonArray(denied) },
            });
        }

        if (allowed.Count > 0)
        {
            yield return Forbidden(new JsonObject
            {
                ["not"] = new JsonArray
                {
                    new JsonObject { ["client_ip"] = new JsonObject { ["ranges"] = ToJsonArray(allowed) } },
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

    /// <summary>
    /// caddy-ratelimit plugin handler: N events per minute, keyed by client IP.
    /// <para>
    /// The key is the same client IP the access rules match on, so a limit and
    /// an allow-list on one route always talk about the same address. Note
    /// <c>{http.request.remote_host}</c> is NOT a real placeholder — the actual
    /// spelling is dot-separated — and an unresolved key degrades to one shared
    /// bucket for every client, turning a per-IP limit into a global one.
    /// </para>
    /// </summary>
    private static JsonObject BuildRateLimitHandler(int perMinute) => new()
    {
        ["handler"] = "rate_limit",
        ["rate_limit"] = new JsonObject
        {
            ["zones"] = new JsonObject
            {
                ["per_route"] = new JsonObject
                {
                    ["key"] = "{http.vars.client_ip}",
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

    private static void AddIfPositive(JsonObject target, string key, int seconds)
    {
        if (seconds > 0) target[key] = Seconds(seconds);
    }

    private static string Seconds(int value) => $"{value}s";

    /// <summary>
    /// Caddy's protocol_min lookup accepts only "tls1.2" and "tls1.3" and has
    /// no ok-check, so anything else — including "tls1.0", "tls1.1" and a
    /// wrong-cased "TLS1.2" — loads without complaint and then does nothing.
    /// A silent no-op on the TLS floor is the wrong failure mode, so anything
    /// unrecognised lands on 1.2 rather than on Caddy's own default.
    /// </summary>
    private static string NormalizeTlsVersion(string? version)
    {
        var v = version?.Trim().ToLowerInvariant();
        return v is "tls1.3" ? "tls1.3" : "tls1.2";
    }

    /// <summary>
    /// Whether an entry is something Caddy's static IP source will accept.
    /// Entries that are not are dropped rather than emitted, because Caddy
    /// refuses to start on a malformed range — this config is also the one
    /// written at startup, so a stray character in appsettings would mean the
    /// proxy never comes up at all rather than coming up slightly wrong.
    /// <para>
    /// Dropping fails closed: an entry that is not emitted is a proxy that is
    /// not trusted, so its X-Forwarded-For is ignored and the access rules fall
    /// back to the peer address. That is more restrictive, never less.
    /// </para>
    /// </summary>
    private static bool IsIpOrCidr(string entry)
    {
        // A zone suffix parses as an address but is rejected by the static IP
        // source specifically, so it has to be screened out here.
        if (entry.Contains('%')) return false;

        var slash = entry.IndexOf('/');
        if (slash < 0) return System.Net.IPAddress.TryParse(entry, out _);

        if (!System.Net.IPAddress.TryParse(entry[..slash], out var addr)) return false;
        if (!int.TryParse(entry[(slash + 1)..], out var bits)) return false;
        var max = addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        return bits >= 0 && bits <= max;
    }

    private static bool UsesTls(IReadOnlyList<string> upstreams) =>
        upstreams.Any(u => Uri.TryCreate(u, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps);

    private static List<string> ParseCsv(string? csv) =>
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
