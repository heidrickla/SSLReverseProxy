using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Persistence;

namespace SslReverseProxy.Api.Endpoints;

public static class ServerEndpoints
{
    public static IEndpointRouteBuilder MapServerEndpoints(this IEndpointRouteBuilder app)
    {
        var servers = app.MapGroup("/api/servers").WithTags("Servers");

        servers.MapGet("/", async (AppDbContext db) =>
            Results.Ok((await db.Servers.AsNoTracking().Include(s => s.Rules).ToListAsync())
                .Select(s => s.ToDto())))
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead));

        servers.MapPost("/", async (
            CreateServerRequest req, AppDbContext db, ProxyTargetValidator validator,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var domainCheck = validator.ValidateDomain(req.Host);
            if (!domainCheck.Ok && !System.Net.IPAddress.TryParse(req.Host, out _))
                return Results.ValidationProblem(new Dictionary<string, string[]>
                    { ["host"] = [domainCheck.Reason ?? "Invalid host."] });

            var server = new ProxyServer
            {
                Name = req.Name.Trim(),
                Host = req.Host.Trim(),
                Os = req.Os == "windows" ? "windows" : "linux",
            };
            db.Servers.Add(server);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Create Server", "Server", server.Name);
            return Results.Created($"/api/servers/{server.Id}", server.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerWrite));

        servers.MapDelete("/{id:guid}", async (
            Guid id, AppDbContext db, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var server = await db.Servers.FindAsync([id], ctx.RequestAborted);
            if (server is null) return Results.NotFound();
            db.Servers.Remove(server);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Delete Server", "Server", server.Name);
            return Results.NoContent();
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerWrite));

        // Rules nested under a server.
        servers.MapGet("/{serverId:guid}/rules", async (Guid serverId, AppDbContext db) =>
            Results.Ok((await db.Rules.AsNoTracking().Where(r => r.ServerId == serverId).ToListAsync())
                .Select(r => r.ToDto())))
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead));

        servers.MapPost("/{serverId:guid}/rules", async (
            Guid serverId, CreateRuleRequest req, AppDbContext db, ProxyTargetValidator validator,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            if (!await db.Servers.AnyAsync(s => s.Id == serverId, ctx.RequestAborted))
                return Results.NotFound();

            var problem = ValidateRule(req.Domain, req.UpstreamUrl, validator, req.AllowedCidrs, req.DeniedCidrs,
                req.RateLimitPerMinute, req.BasicAuthUsername, req.BasicAuthPassword, req.Hardening,
                existingAdditionalUpstreams: null, isCreate: true);
            if (problem is not null) return problem;

            var rule = new ProxyRule
            {
                ServerId = serverId,
                Domain = req.Domain.Trim(),
                UpstreamUrl = req.UpstreamUrl.Trim(),
                EnableTls = req.EnableTls,
                Enabled = req.Enabled,
                AllowedCidrs = NormalizeCsv(req.AllowedCidrs),
                DeniedCidrs = NormalizeCsv(req.DeniedCidrs),
                RateLimitPerMinute = req.RateLimitPerMinute is > 0 ? req.RateLimitPerMinute : null,
                BasicAuthUsername = string.IsNullOrWhiteSpace(req.BasicAuthUsername) ? null : req.BasicAuthUsername.Trim(),
                BasicAuthPasswordHash = HashBasicAuth(req.BasicAuthUsername, req.BasicAuthPassword),
            };
            ApplyHardening(rule, req.Hardening);
            db.Rules.Add(rule);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Create Proxy Rule", "Proxy Rule", rule.Domain);
            SetETag(ctx, rule.Version);
            return Results.Created($"/api/servers/{serverId}/rules/{rule.Id}", rule.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.RuleWrite));

        servers.MapPut("/{serverId:guid}/rules/{ruleId:guid}", async (
            Guid serverId, Guid ruleId, UpdateRuleRequest req, AppDbContext db, ProxyTargetValidator validator,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var rule = await db.Rules.FirstOrDefaultAsync(r => r.Id == ruleId && r.ServerId == serverId, ctx.RequestAborted);
            if (rule is null) return Results.NotFound();

            // A full-replace PUT built from a stale copy silently reverts whatever
            // the other writer changed, so the caller has to say which version it
            // believes it is replacing.
            if (CheckIfMatch(ctx, rule.Version, required: true) is { } precondition)
                return precondition;

            var problem = ValidateRule(req.Domain, req.UpstreamUrl, validator, req.AllowedCidrs, req.DeniedCidrs,
                req.RateLimitPerMinute, req.BasicAuthUsername, req.BasicAuthPassword, req.Hardening,
                existingAdditionalUpstreams: rule.AdditionalUpstreams, isCreate: false);
            if (problem is not null) return problem;

            rule.Domain = req.Domain.Trim();
            rule.UpstreamUrl = req.UpstreamUrl.Trim();
            rule.EnableTls = req.EnableTls;
            rule.Enabled = req.Enabled;
            rule.AllowedCidrs = NormalizeCsv(req.AllowedCidrs);
            rule.DeniedCidrs = NormalizeCsv(req.DeniedCidrs);
            rule.RateLimitPerMinute = req.RateLimitPerMinute is > 0 ? req.RateLimitPerMinute : null;
            rule.BasicAuthUsername = string.IsNullOrWhiteSpace(req.BasicAuthUsername) ? null : req.BasicAuthUsername.Trim();
            // Only re-hash when a new password is supplied; blank username clears auth.
            if (string.IsNullOrWhiteSpace(req.BasicAuthUsername))
                rule.BasicAuthPasswordHash = null;
            else if (!string.IsNullOrEmpty(req.BasicAuthPassword))
                rule.BasicAuthPasswordHash = HashBasicAuth(req.BasicAuthUsername, req.BasicAuthPassword);
            ApplyHardening(rule, req.Hardening);
            rule.UpdatedAt = DateTimeOffset.UtcNow;
            rule.Version++;

            if (await SaveOrConflictAsync(db, ctx) is { } conflict)
            {
                await audit.AuditAsync(me, ctx, "Update Proxy Rule", "Proxy Rule", rule.Domain,
                    success: false, details: "Lost a concurrent update.");
                return conflict;
            }
            await audit.AuditAsync(me, ctx, "Update Proxy Rule", "Proxy Rule", rule.Domain);
            SetETag(ctx, rule.Version);
            return Results.Ok(rule.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.RuleWrite));

        // Quick enable/disable toggle without a full update.
        servers.MapPatch("/{serverId:guid}/rules/{ruleId:guid}/enabled", async (
            Guid serverId, Guid ruleId, ToggleRuleRequest req, AppDbContext db,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var rule = await db.Rules.FirstOrDefaultAsync(r => r.Id == ruleId && r.ServerId == serverId, ctx.RequestAborted);
            if (rule is null) return Results.NotFound();

            // Optional here, unlike PUT: this writes one boolean rather than the
            // whole rule, so losing a race costs an enable/disable rather than
            // an operator's edits. Still enforced when it is supplied.
            if (CheckIfMatch(ctx, rule.Version, required: false) is { } precondition)
                return precondition;

            rule.Enabled = req.Enabled;
            rule.UpdatedAt = DateTimeOffset.UtcNow;
            rule.Version++;
            if (await SaveOrConflictAsync(db, ctx) is { } conflict) return conflict;
            await audit.AuditAsync(me, ctx, req.Enabled ? "Enable Proxy Rule" : "Disable Proxy Rule", "Proxy Rule", rule.Domain);
            SetETag(ctx, rule.Version);
            return Results.Ok(rule.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.RuleWrite));

        // Probe the rule's upstream for reachability (SSRF policy re-applied).
        servers.MapGet("/{serverId:guid}/rules/{ruleId:guid}/health", async (
            Guid serverId, Guid ruleId, AppDbContext db, IUpstreamHealthChecker checker, CancellationToken ct) =>
        {
            var rule = await db.Rules.AsNoTracking().FirstOrDefaultAsync(r => r.Id == ruleId && r.ServerId == serverId, ct);
            if (rule is null) return Results.NotFound();
            var h = await checker.CheckAsync(rule.UpstreamUrl, ct);
            return Results.Ok(new UpstreamHealthDto(h.Reachable, h.StatusCode, h.LatencyMs, h.Error));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead));

        servers.MapDelete("/{serverId:guid}/rules/{ruleId:guid}", async (
            Guid serverId, Guid ruleId, AppDbContext db, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var rule = await db.Rules.FirstOrDefaultAsync(r => r.Id == ruleId && r.ServerId == serverId, ctx.RequestAborted);
            if (rule is null) return Results.NotFound();
            if (CheckIfMatch(ctx, rule.Version, required: false) is { } precondition)
                return precondition;

            db.Rules.Remove(rule);
            if (await SaveOrConflictAsync(db, ctx) is { } conflict) return conflict;
            await audit.AuditAsync(me, ctx, "Delete Proxy Rule", "Proxy Rule", rule.Domain);
            return Results.NoContent();
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.RuleWrite));

        return app;
    }

    /// <summary>
    /// Compares the caller's If-Match against the rule's current version.
    /// Returns null to proceed, or the response to send instead.
    /// <para>
    /// 428 when it is required and absent, rather than quietly proceeding: a
    /// caller that has not been told about preconditions is exactly the caller
    /// whose blind overwrite this exists to prevent. 412 when it is present and
    /// stale.
    /// </para>
    /// </summary>
    private static IResult? CheckIfMatch(HttpContext ctx, int currentVersion, bool required)
    {
        var header = ctx.Request.Headers.IfMatch.ToString();

        if (string.IsNullOrWhiteSpace(header))
        {
            return required
                ? Results.Problem(
                    title: "Precondition Required",
                    detail: $"Send If-Match with the rule's current version (now \"{currentVersion}\") " +
                            "so a concurrent edit is not silently overwritten.",
                    statusCode: StatusCodes.Status428PreconditionRequired)
                : null;
        }

        // "*" is RFC 7232's "any current representation", and the rule existing
        // is already established by the time we reach here.
        if (header.Trim() == "*") return null;

        var matches = header
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(tag => tag.StartsWith("W/", StringComparison.Ordinal) ? tag[2..] : tag)
            .Select(tag => tag.Trim('"'))
            .Any(tag => int.TryParse(tag, out var v) && v == currentVersion);

        return matches
            ? null
            : Results.Problem(
                title: "Precondition Failed",
                detail: $"The rule changed since you loaded it (now version \"{currentVersion}\"). " +
                        "Reload it and reapply your changes.",
                statusCode: StatusCodes.Status412PreconditionFailed);
    }

    private static void SetETag(HttpContext ctx, int version) =>
        ctx.Response.Headers.ETag = $"\"{version}\"";

    /// <summary>
    /// Saves, turning a lost race into 409. The If-Match check narrows the
    /// window but cannot close it: another writer can still land between our
    /// read and our write, and only the database is in a position to notice.
    /// </summary>
    private static async Task<IResult?> SaveOrConflictAsync(AppDbContext db, HttpContext ctx)
    {
        try
        {
            await db.SaveChangesAsync(ctx.RequestAborted);
            return null;
        }
        catch (DbUpdateConcurrencyException)
        {
            return Results.Problem(
                title: "Conflict",
                detail: "Another change to this rule landed while this one was being applied. " +
                        "Reload it and reapply your changes.",
                statusCode: StatusCodes.Status409Conflict);
        }
    }

    private static IResult? ValidateRule(
        string domain, string upstream, ProxyTargetValidator validator,
        string? allowedCidrs, string? deniedCidrs,
        int? rateLimitPerMinute, string? basicAuthUsername, string? basicAuthPassword,
        RuleHardeningRequest? hardening, string? existingAdditionalUpstreams, bool isCreate)
    {
        var errors = new Dictionary<string, string[]>();
        var d = validator.ValidateDomain(domain);
        if (!d.Ok) errors["domain"] = [d.Reason!];
        var u = validator.ValidateUpstream(upstream);
        if (!u.Ok) errors["upstreamUrl"] = [u.Reason!];
        if (InvalidCidr(allowedCidrs) is { } a) errors["allowedCidrs"] = [a];
        if (InvalidCidr(deniedCidrs) is { } dn) errors["deniedCidrs"] = [dn];
        if (rateLimitPerMinute is < 1 or > 100000)
            errors["rateLimitPerMinute"] = ["Rate limit must be between 1 and 100000 requests/minute."];
        // On create, a basic-auth username requires a password (nothing to keep).
        if (isCreate && !string.IsNullOrWhiteSpace(basicAuthUsername) && string.IsNullOrEmpty(basicAuthPassword))
            errors["basicAuthPassword"] = ["A password is required when a basic-auth username is set."];
        ValidateHardening(hardening, upstream, validator, errors);

        // Checked against the upstreams the rule will actually END UP with, not
        // just the ones in this request. On an update that changes only
        // upstreamUrl and omits `hardening`, the stored additional upstreams
        // survive untouched — so validating the request alone would let the
        // primary's scheme drift away from them and leave a mixed-scheme rule.
        // Caddy picks TLS-to-the-backend on the transport, which every upstream
        // in the handler shares. Because one https member turns TLS on for the
        // whole set, a mixed rule always fails the safe way — TLS offered to a
        // plaintext port, so those backends just fail the handshake — never the
        // other way round. That is an availability bug, not a downgrade: the
        // edit returns 200 and then a share of traffic 502s.
        var effectiveExtras = hardening is not null
            ? hardening.AdditionalUpstreams
            : existingAdditionalUpstreams;
        if (!string.IsNullOrWhiteSpace(effectiveExtras) &&
            !errors.ContainsKey("hardening.additionalUpstreams") &&
            SchemesDiffer(upstream, SplitCsv(effectiveExtras)))
        {
            errors["hardening.additionalUpstreams"] =
                ["All upstreams for a rule must use the same scheme as the primary upstream."];
        }

        return errors.Count > 0 ? Results.ValidationProblem(errors) : null;
    }

    // Caddy's built-in upstream selection policies that need no extra config.
    private static readonly HashSet<string> LoadBalancePolicies = new(StringComparer.OrdinalIgnoreCase)
        { "random", "random_choose", "first", "round_robin", "least_conn", "ip_hash", "uri_hash", "client_ip_hash" };

    private static void ValidateHardening(
        RuleHardeningRequest? h, string primaryUpstream, ProxyTargetValidator validator,
        Dictionary<string, string[]> errors)
    {
        if (h is null) return;

        // Every extra upstream is a proxy target like any other, so it goes
        // through the same SSRF policy as the primary. Skipping this would make
        // the additional-upstreams field a way around ValidateUpstream.
        if (!string.IsNullOrWhiteSpace(h.AdditionalUpstreams))
        {
            var bad = new List<string>();
            foreach (var entry in SplitCsv(h.AdditionalUpstreams))
            {
                var check = validator.ValidateUpstream(entry);
                if (!check.Ok) bad.Add($"'{entry}': {check.Reason}");
            }
            if (bad.Count > 0) errors["hardening.additionalUpstreams"] = [.. bad];
        }

        if (!string.IsNullOrWhiteSpace(h.LoadBalancePolicy) && !LoadBalancePolicies.Contains(h.LoadBalancePolicy))
            errors["hardening.loadBalancePolicy"] =
                [$"Unsupported policy. Use one of: {string.Join(", ", LoadBalancePolicies.Order())}."];

        // Upper bounds are sanity rails, not policy: they stop a typo like
        // "3000" seconds from silently becoming a 50-minute upstream timeout.
        AddIfOutOfRange(errors, "hardening.dialTimeoutSeconds", h.DialTimeoutSeconds, 1, 600);
        AddIfOutOfRange(errors, "hardening.upstreamReadTimeoutSeconds", h.UpstreamReadTimeoutSeconds, 1, 3600);
        AddIfOutOfRange(errors, "hardening.upstreamWriteTimeoutSeconds", h.UpstreamWriteTimeoutSeconds, 1, 3600);
        AddIfOutOfRange(errors, "hardening.hstsMaxAgeDays", h.HstsMaxAgeDays, 1, 730);
        AddIfOutOfRange(errors, "hardening.healthCheckIntervalSeconds", h.HealthCheckIntervalSeconds, 1, 86400);
        AddIfOutOfRange(errors, "hardening.healthCheckTimeoutSeconds", h.HealthCheckTimeoutSeconds, 1, 300);

        if (h.MaxRequestBodyBytes is < 1 or > 68_719_476_736)
            errors["hardening.maxRequestBodyBytes"] = ["Must be between 1 byte and 64 GiB."];

        if (h.FrameOptions is { } fo && !string.IsNullOrWhiteSpace(fo) &&
            !fo.Equals("DENY", StringComparison.OrdinalIgnoreCase) &&
            !fo.Equals("SAMEORIGIN", StringComparison.OrdinalIgnoreCase))
            errors["hardening.frameOptions"] = ["Must be DENY or SAMEORIGIN."];

        if (!string.IsNullOrWhiteSpace(h.HealthCheckPath) && !h.HealthCheckPath.StartsWith('/'))
            errors["hardening.healthCheckPath"] = ["Must be a path starting with '/'."];

        // Upstream TLS settings only mean anything when the backend is https,
        // and silently keeping a setting that does nothing invites someone to
        // believe a name mismatch has been dealt with when it has not.
        var upstreamIsTls = Uri.TryCreate(primaryUpstream, UriKind.Absolute, out var pu) &&
                            pu.Scheme == Uri.UriSchemeHttps;
        if (!upstreamIsTls &&
            (!string.IsNullOrWhiteSpace(h.UpstreamTlsServerName) ||
             !string.IsNullOrWhiteSpace(h.UpstreamTlsTrustedCaFile) ||
             h.UpstreamTlsInsecureSkipVerify == true))
        {
            errors["hardening.upstreamTlsServerName"] =
                ["Upstream TLS settings apply only when the upstream URL is https."];
        }

        if (!string.IsNullOrWhiteSpace(h.UpstreamTlsServerName) &&
            Uri.CheckHostName(h.UpstreamTlsServerName.Trim()) == UriHostNameType.Unknown)
            errors["hardening.upstreamTlsServerName"] = ["Must be a valid host name."];

        // Verifying against a private CA and not verifying at all are different
        // intentions. Accepting both would leave it ambiguous which one applied
        // — and Caddy resolves that ambiguity by not checking anything.
        if (h.UpstreamTlsInsecureSkipVerify == true && !string.IsNullOrWhiteSpace(h.UpstreamTlsTrustedCaFile))
            errors["hardening.upstreamTlsInsecureSkipVerify"] =
                ["Cannot skip verification and supply a trusted CA at the same time; skipping ignores the CA."];

        // Caddy accepts either a full status code or a single leading digit
        // standing for the whole class, so 2 means "any 2xx".
        if (h.HealthCheckExpectStatus is { } es && es is not (>= 1 and <= 5) && es is not (>= 100 and <= 599))
            errors["hardening.healthCheckExpectStatus"] =
                ["Must be a status code (100-599) or a single digit for a status class (1-5)."];

        // Compared against the interval that will actually apply. Guarding only
        // when both are supplied let a 300s timeout through against Caddy's 30s
        // default interval, so every check would still be in flight when the
        // next one started.
        if (h.HealthCheckTimeoutSeconds is { } to)
        {
            var effectiveInterval = h.HealthCheckIntervalSeconds ?? DefaultHealthCheckIntervalSeconds;
            if (to > effectiveInterval)
                errors["hardening.healthCheckTimeoutSeconds"] =
                    [$"Timeout must not exceed the check interval ({effectiveInterval}s), or checks overlap."];
        }
    }

    /// <summary>Caddy's own default active health-check interval.</summary>
    private const int DefaultHealthCheckIntervalSeconds = 30;

    private static void AddIfOutOfRange(
        Dictionary<string, string[]> errors, string key, int? value, int min, int max)
    {
        if (value is not null && (value < min || value > max))
            errors[key] = [$"Must be between {min} and {max}."];
    }

    /// <summary>
    /// Copies a supplied hardening block onto the rule. A null block leaves the
    /// rule untouched, so clients that predate these settings keep working; a
    /// supplied block replaces every field, so a null inside it clears that
    /// setting — matching the replace semantics the rest of PUT already has.
    /// </summary>
    private static void ApplyHardening(ProxyRule rule, RuleHardeningRequest? h)
    {
        if (h is null) return;

        rule.AdditionalUpstreams = NormalizeCsv(h.AdditionalUpstreams);
        rule.LoadBalancePolicy = string.IsNullOrWhiteSpace(h.LoadBalancePolicy)
            ? null : h.LoadBalancePolicy.Trim().ToLowerInvariant();
        rule.DialTimeoutSeconds = h.DialTimeoutSeconds;
        rule.UpstreamReadTimeoutSeconds = h.UpstreamReadTimeoutSeconds;
        rule.UpstreamWriteTimeoutSeconds = h.UpstreamWriteTimeoutSeconds;
        rule.MaxRequestBodyBytes = h.MaxRequestBodyBytes;
        rule.EnableSecurityHeaders = h.EnableSecurityHeaders ?? true;
        rule.UpstreamTlsServerName = string.IsNullOrWhiteSpace(h.UpstreamTlsServerName)
            ? null : h.UpstreamTlsServerName.Trim();
        rule.UpstreamTlsTrustedCaFile = string.IsNullOrWhiteSpace(h.UpstreamTlsTrustedCaFile)
            ? null : h.UpstreamTlsTrustedCaFile.Trim();
        rule.UpstreamTlsInsecureSkipVerify = h.UpstreamTlsInsecureSkipVerify ?? false;
        rule.HstsMaxAgeDays = h.HstsMaxAgeDays;
        rule.HstsIncludeSubdomains = h.HstsIncludeSubdomains ?? false;
        rule.FrameOptions = string.IsNullOrWhiteSpace(h.FrameOptions)
            ? null : h.FrameOptions.Trim().ToUpperInvariant();
        rule.HealthCheckPath = string.IsNullOrWhiteSpace(h.HealthCheckPath) ? null : h.HealthCheckPath.Trim();
        rule.HealthCheckIntervalSeconds = h.HealthCheckIntervalSeconds;
        rule.HealthCheckTimeoutSeconds = h.HealthCheckTimeoutSeconds;
        rule.HealthCheckExpectStatus = h.HealthCheckExpectStatus;
        rule.SkipAccessLog = h.SkipAccessLog ?? false;
    }

    private static bool SchemesDiffer(string primary, IEnumerable<string> others)
    {
        if (!Uri.TryCreate(primary, UriKind.Absolute, out var p)) return false;
        return others.Any(o => Uri.TryCreate(o, UriKind.Absolute, out var u) &&
                               !string.Equals(u.Scheme, p.Scheme, StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<string> SplitCsv(string csv) =>
        csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string? NormalizeCsv(string? csv)
    {
        if (string.IsNullOrWhiteSpace(csv)) return null;
        var parts = SplitCsv(csv).ToArray();
        return parts.Length == 0 ? null : string.Join(",", parts);
    }

    // Returns an error message if any entry is not a valid IP or CIDR, else null.
    private static string? InvalidCidr(string? csv)
    {
        if (string.IsNullOrWhiteSpace(csv)) return null;
        foreach (var entry in csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var slash = entry.IndexOf('/');
            var addr = slash >= 0 ? entry[..slash] : entry;
            if (!System.Net.IPAddress.TryParse(addr, out _))
                return $"'{entry}' is not a valid IP or CIDR range.";
            if (slash >= 0 && (!int.TryParse(entry[(slash + 1)..], out var bits) || bits < 0 || bits > 128))
                return $"'{entry}' has an invalid CIDR prefix length.";
        }
        return null;
    }

    // Hash the basic-auth password with bcrypt. Returns null when no auth is set.
    private static string? HashBasicAuth(string? username, string? password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password)) return null;
        return BCrypt.Net.BCrypt.HashPassword(password);
    }
}
