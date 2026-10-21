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
    private const string AccessLoggerId = RecentRequests.AccessLoggerPrefix + AccessLogName;
    private const string RecentLogName = "recent";

    /// <summary>Server for TLS-enabled rules, on <see cref="ProxyOptions.HttpsPort"/>.</summary>
    public const string HttpsServer = "https";

    /// <summary>
    /// Server for plaintext rules, on <see cref="ProxyOptions.HttpPort"/>.
    /// Automatic HTTPS adds its redirects and ACME challenges to it.
    /// </summary>
    public const string HttpServer = "http";

    /// <summary>Renewal window that puts a certificate due for renewal at once (a forced renewal).</summary>
    public const double ForcedRenewalRatio = 0.99999;

    public static JsonObject Build(IReadOnlyCollection<ProxyRule> rules, ProxyOptions options) =>
        Build(new ProxyPlan(rules), options);

    public static JsonObject Build(ProxyPlan plan, ProxyOptions options)
    {
        var rules = plan.Rules;
        // Caddy runs the first matching terminal route, so the longest path prefix
        // goes first and a host's whole-host rule last. OrderBy is stable.
        var active = rules.Where(r => r.Enabled)
            .OrderByDescending(r => r.PathPrefix?.Length ?? -1)
            .ToList();

        // The API refuses braces; this holds the line for rows written before it did.
        if (active.FirstOrDefault(r => r.PlaceholderFields().Any()) is { } braced)
            throw new InvalidOperationException(
                $"Rule '{braced.Domain}{braced.PathPrefix}' has '{{' or '}}' in {string.Join(", ", braced.PlaceholderFields())}.");
        var tlsRoutes = new JsonArray();
        var plainRoutes = new JsonArray();

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

            // Names the rule in its access log entries, before any handler that can answer.
            if (AccessLogged(options))
                handle.Add(new JsonObject { ["handler"] = "log_append", ["key"] = RecentRequests.RuleField, ["value"] = rule.Id.ToString() });

            // Per-route access control (evaluated before proxying). Deny wins.
            foreach (var acl in BuildAccessControlHandlers(rule))
                handle.Add(acl);

            // Rate limit (caddy-ratelimit plugin) — requires the plugin in the build.
            if (rule.RateLimitPerMinute is > 0)
                handle.Add(BuildRateLimitHandler(rule.Id, rule.RateLimitPerMinute.Value));

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

            // After Basic Auth, so a rule with both needs both; before the rewrite, so the provider sees the client's path.
            if (rule.SignInProvider is { } provider)
                handle.Add(BuildSignInHandler(rule, provider, options));

            // Caddy's strip is case-insensitive like its path matcher and leaves "/"
            // when the whole path was the prefix.
            if (rule.StripPathPrefix && rule.PathPrefix is { } strip)
                handle.Add(new JsonObject { ["handler"] = "rewrite", ["strip_path_prefix"] = strip });

            handle.Add(BuildReverseProxyHandler(rule));

            var match = new JsonObject { ["host"] = new JsonArray { rule.Domain } };
            if (rule.PathPrefix is { } prefix)
                match["path"] = new JsonArray { prefix, prefix + "/*" };

            (rule.EnableTls ? tlsRoutes : plainRoutes).Add(new JsonObject
            {
                ["match"] = new JsonArray { match },
                ["handle"] = handle,
                ["terminal"] = true,
            });
        }

        // A provider's own sign-in paths on each host that uses it, ahead of the host's rules.
        foreach (var callback in BuildSignInCallbackRoutes(active).Reverse())
            (callback.Tls ? tlsRoutes : plainRoutes).Insert(0, callback.Route);

        // One server per port. A TLS host's route on a server that also listens
        // on the HTTP port is proxied in plaintext there, because automatic
        // HTTPS appends its redirect after the host's own route.
        var servers = new JsonObject();

        // Only when something is served over TLS. A connection policy is what
        // makes the HTTPS port a TLS listener, so the server without one would
        // answer plaintext on it.
        //
        // A single policy with no "match" is a catch-all, so it applies to every
        // connection while leaving SNI-based certificate selection alone. If
        // every policy carried a match, a handshake matching none would die
        // before any certificate was chosen.
        // Manual names Caddy obtains with no route naming them. The HTTPS listener exists for them
        // too, so they are served by SNI and the certificate monitor can read them.
        var automated = plan.Certificates.Where(c => c.Automate && ChallengeReady(c, options))
            .Select(c => c.Domain).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToList();

        if (tlsRoutes.Count > 0 || automated.Count > 0)
        {
            var policy = new JsonObject { ["protocol_min"] = NormalizeTlsVersion(options.TlsMinVersion) };
            var ciphers = ParseCsv(options.TlsCipherSuites);
            if (ciphers.Count > 0) policy["cipher_suites"] = ToJsonArray(ciphers);
            var https = Server(options.HttpsPort, tlsRoutes, active, options);
            https["tls_connection_policies"] = new JsonArray { policy };
            servers[HttpsServer] = https;
        }

        // Always present: it carries the redirects for the TLS hosts. Listening
        // only on the HTTP port keeps automatic HTTPS off the plaintext hosts.
        servers[HttpServer] = Server(options.HttpPort, plainRoutes, active, options);

        var http = new JsonObject
        {
            ["servers"] = servers,
            ["metrics"] = new JsonObject(),
        };
        // Automatic HTTPS redirects to, and answers ACME challenges on, these ports.
        if (options.HttpPort != 80) http["http_port"] = options.HttpPort;
        if (options.HttpsPort != 443) http["https_port"] = options.HttpsPort;
        var apps = new JsonObject { ["http"] = http };

        apps["tls"] = BuildTlsApp(plan, automated, options);

        // Caddy installs its local root in the system trust store by default,
        // which needs elevation and changes the host for every program on it.
        if (UsesInternalIssuer(options))
        {
            apps["pki"] = new JsonObject
            {
                ["certificate_authorities"] = new JsonObject
                {
                    ["local"] = new JsonObject { ["install_trust"] = false },
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

    /// <summary>Settings shared by both servers: client IP, timeouts and the access log.</summary>
    private static JsonObject Server(int port, JsonArray routes, IReadOnlyList<ProxyRule> active, ProxyOptions options)
    {
        var srv = new JsonObject
        {
            ["listen"] = new JsonArray { $":{port}" },
            ["routes"] = routes,
        };

        // Believe X-Forwarded-For only from the proxies we were told about, so
        // the per-rule IP lists match on the real client. With no trust list
        // configured, Caddy ignores the header entirely and client_ip is just
        // the peer address — which is the correct default for a proxy that
        // faces clients directly, and unspoofable.
        var trusted = ParseCsv(options.TrustedProxyCidrs).Where(IsIpOrCidr).ToList();
        if (trusted.Count > 0)
        {
            srv["trusted_proxies"] = new JsonObject
            {
                ["source"] = "static",
                ["ranges"] = ToJsonArray(trusted),
            };
            // Strict parsing walks X-Forwarded-For right to left and stops at
            // the first hop that is not trusted. Without it Caddy takes the
            // leftmost entry, which the client wrote and can therefore forge —
            // and forging it is exactly how you would walk through an allow-list.
            srv["trusted_proxies_strict"] = 1;
        }

        AddIfPositive(srv, "read_timeout", options.ReadTimeoutSeconds);
        AddIfPositive(srv, "read_header_timeout", options.ReadHeaderTimeoutSeconds);
        AddIfPositive(srv, "write_timeout", options.WriteTimeoutSeconds);
        AddIfPositive(srv, "idle_timeout", options.IdleTimeoutSeconds);

        if (AccessLogged(options))
        {
            var logs = new JsonObject { ["default_logger_name"] = AccessLogName };
            var skip = active.Where(r => r.SkipAccessLog).Select(r => r.Domain)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (skip.Count > 0) logs["skip_hosts"] = ToJsonArray(skip);
            srv["logs"] = logs;
        }

        return srv;
    }

    private static bool AccessLogged(ProxyOptions options) =>
        options.RecentRequests || !string.IsNullOrWhiteSpace(options.AccessLogPath);

    /// <summary>
    /// Routes the data-plane access log to its own file, and a filtered copy to stderr for
    /// <see cref="RecentRequests"/>. The default logger excludes it, otherwise every request is
    /// written again in Caddy's own stderr log.
    /// </summary>
    private static JsonObject? BuildLogging(ProxyOptions options)
    {
        if (!AccessLogged(options)) return null;

        var logs = new JsonObject();
        if (!string.IsNullOrWhiteSpace(options.AccessLogPath))
        {
            logs[AccessLogName] = new JsonObject
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
            };
        }
        if (options.RecentRequests)
        {
            var drop = new JsonObject { ["filter"] = "delete" };
            logs[RecentLogName] = new JsonObject
            {
                ["include"] = new JsonArray { AccessLoggerId },
                ["writer"] = new JsonObject { ["output"] = "stderr" },
                ["encoder"] = new JsonObject
                {
                    ["format"] = "filter",
                    ["wrap"] = new JsonObject { ["format"] = "json" },
                    ["fields"] = new JsonObject
                    {
                        ["request>headers"] = drop.DeepClone(),
                        ["request>tls"] = drop.DeepClone(),
                        ["request>remote_ip"] = drop.DeepClone(),
                        ["request>remote_port"] = drop.DeepClone(),
                        ["resp_headers"] = drop.DeepClone(),
                        ["user_id"] = drop.DeepClone(),
                        ["request>uri"] = new JsonObject { ["filter"] = "regexp", ["regexp"] = "[?#].*$", ["value"] = "" },
                    },
                },
                ["level"] = "INFO",
            };
        }
        logs["default"] = new JsonObject { ["exclude"] = new JsonArray { AccessLoggerId } };
        return new JsonObject { ["logs"] = logs };
    }

    /// <summary>
    /// Certificate automation. certmagic takes the first policy whose subjects match a name and a
    /// policy without subjects matches every name, so the per-name policies come before the catch-all.
    /// </summary>
    private static JsonObject BuildTlsApp(ProxyPlan plan, IReadOnlyList<string> automated, ProxyOptions options)
    {
        // Caddy fixes the maintenance interval when its certificate cache is created, which is the
        // first config the process loads; every config carries it so that one does too.
        var automation = new JsonObject { ["renew_interval"] = Seconds(Math.Max(1, options.RenewCheckSeconds)) };

        var policies = new JsonArray();
        var named = plan.Certificates
            .Where(c => c.RenewPending || (c.Challenge == CertificateChallenge.DnsCloudflare && ChallengeReady(c, options)))
            .GroupBy(c => c.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(c => c.Domain, StringComparer.Ordinal);
        foreach (var c in named)
        {
            var policy = new JsonObject { ["subjects"] = new JsonArray { c.Domain } };
            if (SubjectIssuer(c, options) is { } subjectIssuer)
                policy["issuers"] = new JsonArray { subjectIssuer };
            // Due for renewal at once, so Caddy's next maintenance pass reissues it in place while the
            // current certificate keeps serving. The monitor drops this once a new serial is served.
            if (c.RenewPending)
                policy["renewal_window_ratio"] = ForcedRenewalRatio;
            policies.Add(policy);
        }
        if (BuildIssuer(options) is { } issuer)
            policies.Add(new JsonObject { ["issuers"] = new JsonArray { issuer } });
        if (policies.Count > 0)
            automation["policies"] = policies;

        var tls = new JsonObject { ["automation"] = automation };
        if (automated.Count > 0)
            tls["certificates"] = new JsonObject { ["automate"] = ToJsonArray(automated) };
        return tls;
    }

    /// <summary>
    /// Whether the name can be obtained as configured: a DNS challenge needs a usable Cloudflare token,
    /// and a wildcard needs DNS unless Caddy's internal CA signs it.
    /// </summary>
    public static bool ChallengeReady(CertificatePlan c, ProxyOptions options)
    {
        if (UsesInternalIssuer(options)) return true;
        if (c.Challenge == CertificateChallenge.DnsCloudflare) return CloudflareToken.Usable(options);
        return !CertificateNames.IsWildcard(c.Domain);
    }

    private static JsonObject? SubjectIssuer(CertificatePlan c, ProxyOptions options)
    {
        if (UsesInternalIssuer(options) || c.Challenge != CertificateChallenge.DnsCloudflare)
            return BuildIssuer(options);
        var acme = AcmeIssuer(options);
        var dns = new JsonObject
        {
            ["provider"] = new JsonObject
            {
                ["name"] = "cloudflare",
                // Caddy reads the value from its own environment; the config never holds it.
                ["api_token"] = "{env." + CaddyEnvironment.CloudflareTokenVariable + "}",
            },
        };
        var resolvers = ParseCsv(options.DnsChallengeResolvers);
        if (resolvers.Count > 0) dns["resolvers"] = ToJsonArray(resolvers);
        acme["challenges"] = new JsonObject { ["dns"] = dns };
        return acme;
    }

    public static bool UsesInternalIssuer(ProxyOptions options) =>
        string.Equals(options.CertificateIssuer?.Trim(), "internal", StringComparison.OrdinalIgnoreCase);

    /// <summary>Null leaves Caddy's default issuers (Let's Encrypt, then ZeroSSL) in place.</summary>
    private static JsonObject? BuildIssuer(ProxyOptions options)
    {
        if (UsesInternalIssuer(options))
            return new JsonObject { ["module"] = "internal" };
        if (string.IsNullOrWhiteSpace(options.AcmeContactEmail) && !options.UseAcmeStaging)
            return null;
        return AcmeIssuer(options);
    }

    private static JsonObject AcmeIssuer(ProxyOptions options)
    {
        var acme = new JsonObject
        {
            ["module"] = "acme",
            ["ca"] = options.UseAcmeStaging
                ? "https://acme-staging-v02.api.letsencrypt.org/directory"
                : "https://acme-v02.api.letsencrypt.org/directory",
        };
        if (!string.IsNullOrWhiteSpace(options.AcmeContactEmail))
            acme["email"] = options.AcmeContactEmail;
        return acme;
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
        {
            // Any tls object at all is what selects HTTPS to the backend; the
            // members below only shape how the backend's certificate is judged.
            var upstreamTls = new JsonObject();

            if (!string.IsNullOrWhiteSpace(rule.UpstreamTlsServerName))
                upstreamTls["server_name"] = rule.UpstreamTlsServerName!.Trim();

            // The tls.ca_pool.source module, not the older root_ca_pem_files —
            // that one still loads but Caddy logs it as deprecated.
            if (!string.IsNullOrWhiteSpace(rule.UpstreamTlsTrustedCaFile))
            {
                upstreamTls["ca"] = new JsonObject
                {
                    ["provider"] = "file",
                    ["pem_files"] = new JsonArray { rule.UpstreamTlsTrustedCaFile!.Trim() },
                };
            }

            if (rule.UpstreamTlsInsecureSkipVerify)
                upstreamTls["insecure_skip_verify"] = true;

            transport["tls"] = upstreamTls;
        }
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
    /// The plugin keeps limiter state in a process-wide map keyed by zone name and
    /// applies the last provisioned limit to every handler sharing it, so each rule
    /// gets its own zone.
    /// </para>
    /// <para>
    /// The key is the same client IP the access rules match on, so a limit and
    /// an allow-list on one route always talk about the same address. Note
    /// <c>{http.request.remote_host}</c> is NOT a real placeholder — the actual
    /// spelling is dot-separated — and an unresolved key degrades to one shared
    /// bucket for every client, turning a per-IP limit into a global one.
    /// </para>
    /// </summary>
    private static JsonObject BuildRateLimitHandler(Guid ruleId, int perMinute) => new()
    {
        ["handler"] = "rate_limit",
        ["rate_limits"] = new JsonObject
        {
            [RateLimitZone(ruleId)] = new JsonObject
            {
                ["key"] = "{http.vars.client_ip}",
                ["max_events"] = perMinute,
                ["window"] = "1m",
            },
        },
    };

    public static string RateLimitZone(Guid ruleId) => $"rule_{ruleId:N}";

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

    /// <summary>
    /// Caddy's <c>forward_auth</c> expansion, as <c>caddy adapt</c> 2.11.7 writes it: a GET to the verify path
    /// with the method and URI in headers; on 2xx each identity header is deleted from the request and set
    /// only when the provider sent it, and the request goes on; any other answer goes to the client. Added to
    /// it: every provider's identity headers are deleted from the verify call and, on 2xx, from the request
    /// before the provider's own are set, so a client cannot send one a different provider would have set.
    /// </summary>
    private static JsonObject BuildSignInHandler(ProxyRule rule, string provider, ProxyOptions options)
    {
        if (!SignInProviders.Profiles.TryGetValue(provider, out var profile))
            throw new InvalidOperationException($"Rule '{rule.Domain}{rule.PathPrefix}' names an unknown sign-in provider '{provider}'.");
        var verifier = provider == SignInProviders.CloudflareAccess ? ControlPlane(options) : rule.SignInVerifierUrl;
        if (string.IsNullOrWhiteSpace(verifier) || !Uri.TryCreate(verifier, UriKind.Absolute, out _))
            throw new InvalidOperationException($"Rule '{rule.Domain}{rule.PathPrefix}' has no verifier address for {profile.Label}.");
        if (provider == SignInProviders.CloudflareAccess
            && (rule.CloudflareTeamDomain is null || rule.CloudflareAudience is null))
            throw new InvalidOperationException($"Rule '{rule.Domain}{rule.PathPrefix}' needs a Cloudflare Access team domain and audience.");

        var good = new JsonArray
        {
            new JsonObject { ["handle"] = new JsonArray { new JsonObject { ["handler"] = "vars" } } },
            new JsonObject
            {
                ["handle"] = new JsonArray { new JsonObject { ["handler"] = "headers", ["request"] = new JsonObject { ["delete"] = IdentityHeaders() } } },
            },
        };
        foreach (var header in profile.CopyHeaders.Order(StringComparer.Ordinal))
        {
            var placeholder = "{http.reverse_proxy.header." + header + "}";
            good.Add(new JsonObject
            {
                ["handle"] = new JsonArray { new JsonObject { ["handler"] = "headers", ["request"] = new JsonObject { ["delete"] = new JsonArray { header } } } },
            });
            good.Add(new JsonObject
            {
                ["handle"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["handler"] = "headers",
                        ["request"] = new JsonObject { ["set"] = new JsonObject { [header] = new JsonArray { placeholder } } },
                    },
                },
                ["match"] = new JsonArray
                {
                    new JsonObject { ["not"] = new JsonArray { new JsonObject { ["vars"] = new JsonObject { [placeholder] = new JsonArray { "" } } } } },
                },
            });
        }
        var responses = new JsonArray
        {
            new JsonObject { ["match"] = new JsonObject { ["status_code"] = new JsonArray { 2 } }, ["routes"] = good },
        };
        if (profile.SignInOn401 is { } signIn)
        {
            responses.Add(new JsonObject
            {
                ["match"] = new JsonObject { ["status_code"] = new JsonArray { 401 } },
                ["routes"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["handle"] = new JsonArray
                        {
                            new JsonObject
                            {
                                ["handler"] = "static_response",
                                ["headers"] = new JsonObject { ["Location"] = new JsonArray { signIn } },
                                ["status_code"] = 302,
                            },
                        },
                    },
                },
            });
        }

        var uri = provider == SignInProviders.CloudflareAccess ? profile.VerifyUri + rule.Id : profile.VerifyUri;
        var handler = VerifierProxy(verifier!);
        handler["handle_response"] = responses;
        var set = new JsonObject
        {
            ["X-Forwarded-Method"] = new JsonArray { "{http.request.method}" },
            ["X-Forwarded-Uri"] = new JsonArray { "{http.request.uri}" },
        };
        // The control plane is called by its own name, so its AllowedHosts need not list the proxied hosts.
        if (provider == SignInProviders.CloudflareAccess)
            set["Host"] = new JsonArray { new Uri(verifier!, UriKind.Absolute).Authority };
        handler["headers"] = new JsonObject { ["request"] = new JsonObject { ["set"] = set, ["delete"] = IdentityHeaders() } };
        handler["rewrite"] = new JsonObject { ["method"] = "GET", ["uri"] = uri };
        return handler;
    }

    private static JsonArray IdentityHeaders() => ToJsonArray(SignInProviders.IdentityHeaders);

    /// <summary>
    /// Authentik's outpost and oauth2-proxy's sign-in paths, proxied to the provider on each host whose rules use it,
    /// without the client's identity headers.
    /// </summary>
    private static IEnumerable<(bool Tls, JsonObject Route)> BuildSignInCallbackRoutes(IReadOnlyList<ProxyRule> active)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in active.OrderBy(r => r.Domain, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Id))
        {
            if (rule.SignInProvider is not { } provider || !SignInProviders.Profiles.TryGetValue(provider, out var profile)
                || profile.CallbackPrefix is not { } prefix || string.IsNullOrWhiteSpace(rule.SignInVerifierUrl)) continue;
            if (!seen.Add(rule.Domain.Trim())) continue;
            var proxy = VerifierProxy(rule.SignInVerifierUrl!);
            var request = new JsonObject();
            if (provider == SignInProviders.OAuth2Proxy)
                request["set"] = new JsonObject
                {
                    ["X-Forwarded-Uri"] = new JsonArray { "{http.request.uri}" },
                    ["X-Real-Ip"] = new JsonArray { "{http.request.remote.host}" },
                };
            request["delete"] = IdentityHeaders();
            proxy["headers"] = new JsonObject { ["request"] = request };
            yield return (rule.EnableTls, new JsonObject
            {
                ["match"] = new JsonArray
                {
                    new JsonObject { ["host"] = new JsonArray { rule.Domain }, ["path"] = new JsonArray { prefix + "/*" } },
                },
                ["handle"] = new JsonArray { proxy },
                ["terminal"] = true,
            });
        }
    }

    private static JsonObject VerifierProxy(string url)
    {
        var proxy = new JsonObject
        {
            ["handler"] = "reverse_proxy",
            ["upstreams"] = new JsonArray { new JsonObject { ["dial"] = ToDial(url) } },
        };
        if (new Uri(url, UriKind.Absolute).Scheme == Uri.UriSchemeHttps)
            proxy["transport"] = new JsonObject { ["protocol"] = "http", ["tls"] = new JsonObject() };
        return proxy;
    }

    private static string ControlPlane(ProxyOptions options) =>
        Uri.TryCreate(options.ControlPlaneUrl, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps)
            ? options.ControlPlaneUrl
            : throw new InvalidOperationException("Proxy:ControlPlaneUrl must be the http(s) address Caddy reaches this service at.");

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
