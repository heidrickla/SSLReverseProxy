using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;

namespace SslReverseProxy.Api.Endpoints;

/// <summary>
/// Certificates Caddy obtains and renews. Rows for TLS rules' hosts are kept by the certificate monitor;
/// a manual row names a host or wildcard Caddy obtains with no rule for it.
/// </summary>
public static class CertificateEndpoints
{
    public static IEndpointRouteBuilder MapCertificateEndpoints(this IEndpointRouteBuilder app)
    {
        var certs = app.MapGroup("/api/certificates").WithTags("Certificates");

        certs.MapGet("/", async (AppDbContext db, TimeProvider clock, CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            var rows = await db.Certificates.AsNoTracking().ToListAsync(ct);
            return Results.Ok(rows.OrderBy(c => c.Domain, StringComparer.Ordinal).Select(c => c.ToDto(now)));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertRead));

        // The validation methods this server can use, for the add form. Never includes the token.
        certs.MapGet("/challenges", (IOptions<ProxyOptions> options) =>
        {
            var o = options.Value;
            var internalCa = CaddyConfigBuilder.UsesInternalIssuer(o);
            var dnsProblem = internalCa ? null : CloudflareToken.Problem(o);
            return Results.Ok(new[]
            {
                new ChallengeDto(nameof(CertificateChallenge.Http), true, internalCa, null),
                new ChallengeDto(nameof(CertificateChallenge.DnsCloudflare), dnsProblem is null, true, dnsProblem),
            });
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertRead));

        certs.MapGet("/{id:guid}/status", async (Guid id, AppDbContext db, TimeProvider clock, CancellationToken ct) =>
        {
            var cert = await db.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct);
            if (cert is null) return Results.NotFound();
            var health = CertificateStatusEvaluator.Evaluate(cert, clock.GetUtcNow());
            return Results.Ok(new CertStatusDto(cert.Id, cert.Domain, health.Status.ToString(), health.DaysRemaining, cert.ExpiresAt));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertRead));

        certs.MapPost("/", async (
            CreateCertificateRequest req, AppDbContext db, ProxyChanges changes, ICertificateChecks checks,
            IOptions<ProxyOptions> options, TimeProvider clock, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            if (CertificateNames.Problem(req.Domain) is { } nameProblem)
                return Invalid("domain", nameProblem);
            if (!TryChallenge(req.Challenge, out var challenge))
                return Invalid("challenge", "Challenge must be Http or DnsCloudflare.");

            var domain = CertificateNames.Normalize(req.Domain);
            if (ChallengeProblem(domain, challenge, options.Value) is { } challengeProblem)
                return Invalid("challenge", challengeProblem);
            using var change = await changes.EnterAsync(ctx.RequestAborted);
            if (await db.Certificates.AnyAsync(c => c.Domain == domain, ctx.RequestAborted))
                return Results.Conflict(new { message = $"{domain} already has a certificate row." });

            var cert = new Certificate
            {
                Domain = domain,
                Source = CertificateSource.Manual,
                Challenge = challenge,
                Status = CertificateStatus.Issuing,
            };
            db.Certificates.Add(cert);
            try
            {
                await db.SaveChangesAsync(ctx.RequestAborted);
            }
            catch (DbUpdateException)
            {
                return Results.Conflict(new { message = $"{domain} already has a certificate row." });
            }

            var status = await ApplyIfRunningAsync(db, change, ctx.RequestAborted);
            checks.RequestCheck();
            await audit.AuditAsync(me, ctx, "Register Certificate", "Certificate", cert.Domain,
                details: $"challenge={challenge}{ApplyNote(status)}");
            return Results.Created($"/api/certificates/{cert.Id}", cert.ToDto(clock.GetUtcNow()));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertWrite));

        certs.MapPut("/{id:guid}", async (
            Guid id, UpdateCertificateRequest req, AppDbContext db, ProxyChanges changes, ICertificateChecks checks,
            IOptions<ProxyOptions> options, TimeProvider clock, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            using var change = await changes.EnterAsync(ctx.RequestAborted);
            var cert = await db.Certificates.FirstOrDefaultAsync(c => c.Id == id, ctx.RequestAborted);
            if (cert is null) return Results.NotFound();
            if (!TryChallenge(req.Challenge, out var challenge))
                return Invalid("challenge", "Challenge must be Http or DnsCloudflare.");
            if (ChallengeProblem(cert.Domain, challenge, options.Value) is { } challengeProblem)
                return Invalid("challenge", challengeProblem);

            cert.Challenge = challenge;
            await db.SaveChangesAsync(ctx.RequestAborted);
            var status = await ApplyIfRunningAsync(db, change, ctx.RequestAborted);
            checks.RequestCheck();
            await audit.AuditAsync(me, ctx, "Update Certificate", "Certificate", cert.Domain,
                details: $"challenge={challenge}{ApplyNote(status)}");
            return Results.Ok(cert.ToDto(clock.GetUtcNow()));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertWrite));

        // Forced renewal. The config marks the name due for renewal, Caddy reissues it in place at its next
        // maintenance pass, and the certificate monitor drops the mark once a new serial is served.
        certs.MapPost("/{id:guid}/renew", async (
            Guid id, AppDbContext db, ProxyChanges changes, ICertificateChecks checks, ICertificateProbe probe,
            IOptions<ProxyOptions> options, TimeProvider clock, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var ct = ctx.RequestAborted;
            // The mark is read, set and pushed in one scope: a second request sees it, and a rollback waits.
            using var change = await changes.EnterAsync(ct);
            var cert = await db.Certificates.FirstOrDefaultAsync(c => c.Id == id, ct);
            if (cert is null) return Results.NotFound();
            if (!checks.Enabled)
                return Refused("The certificate monitor is off (Proxy:CertificateCheckSeconds is 0), and a forced renewal needs it to finish.");
            if ((await change.StatusAsync(ct)).State != ProxyState.Running)
                return Refused("The proxy is stopped; start it first.");
            if (cert.RenewFromSerial is not null)
                return Refused($"A renewal of {cert.Domain} is already in progress.");

            var now = clock.GetUtcNow();
            var minimumAge = TimeSpan.FromMinutes(Math.Max(0, options.Value.RenewMinimumAgeMinutes));
            if (cert.RenewRequestedAt is { } last && now - last < minimumAge)
                return Refused($"A renewal of {cert.Domain} was requested at {last:u}; the next may be requested {minimumAge.TotalMinutes:0} minutes after it.");

            var served = await probe.ReadAsync(cert.Domain, ct);
            if (served is not { MatchesName: true })
                return Refused($"Caddy is not serving a certificate for {cert.Domain}, so there is nothing to renew.");

            var previous = cert.RenewRequestedAt;
            cert.RenewRequestedAt = now;
            cert.RenewFromSerial = served.Serial;
            await db.SaveChangesAsync(ct);

            var status = await change.ApplyAsync(await db.LoadProxyPlanAsync(ct), ct);
            if (status.State != ProxyState.Running)
            {
                cert.RenewRequestedAt = previous;
                cert.RenewFromSerial = null;
                await db.SaveChangesAsync(CancellationToken.None);
                await audit.AuditAsync(me, ctx, "Renew Certificate", "Certificate", cert.Domain,
                    success: false, details: status.Message);
                return Results.Problem(title: "Renewal not started", detail: status.Message,
                    statusCode: StatusCodes.Status502BadGateway);
            }

            checks.RequestCheck();
            await audit.AuditAsync(me, ctx, "Renew Certificate", "Certificate", cert.Domain,
                details: $"from serial {served.Serial}");
            return Results.Accepted($"/api/certificates/{cert.Id}/status", cert.ToDto(now));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertWrite));

        certs.MapDelete("/{id:guid}", async (
            Guid id, AppDbContext db, ProxyChanges changes, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            using var change = await changes.EnterAsync(ctx.RequestAborted);
            var cert = await db.Certificates.FindAsync([id], ctx.RequestAborted);
            if (cert is null) return Results.NotFound();
            if (cert.Source == CertificateSource.Rule)
                return Refused($"{cert.Domain} is a TLS rule's host; its row goes when no TLS rule names the host.");
            db.Certificates.Remove(cert);
            await db.SaveChangesAsync(ctx.RequestAborted);
            var status = await ApplyIfRunningAsync(db, change, ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Delete Certificate", "Certificate", cert.Domain, details: ApplyNote(status));
            return Results.NoContent();
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertWrite));

        return app;
    }

    private static bool TryChallenge(string? value, out CertificateChallenge challenge)
    {
        challenge = CertificateChallenge.Http;
        if (string.IsNullOrWhiteSpace(value)) return true;
        return Enum.TryParse(value.Trim(), ignoreCase: true, out challenge)
               && Enum.IsDefined(challenge)
               && !int.TryParse(value, out _);
    }

    /// <summary>Why the name cannot be obtained with the challenge, or null when it can.</summary>
    private static string? ChallengeProblem(string domain, CertificateChallenge challenge, ProxyOptions options)
    {
        var plan = new CertificatePlan(domain, challenge, Automate: true, RenewPending: false);
        if (CaddyConfigBuilder.ChallengeReady(plan, options)) return null;
        return challenge == CertificateChallenge.DnsCloudflare
            ? CloudflareToken.Problem(options)
            : "A wildcard certificate needs the DnsCloudflare challenge.";
    }

    /// <summary>Applies the stored plan when the proxy runs. A stopped proxy picks it up when started.</summary>
    private static async Task<ProxyStatus?> ApplyIfRunningAsync(AppDbContext db, ProxyChanges.Scope change, CancellationToken ct)
    {
        if ((await change.StatusAsync(ct)).State != ProxyState.Running) return null;
        return await change.ApplyAsync(await db.LoadProxyPlanAsync(ct), ct);
    }

    private static string? ApplyNote(ProxyStatus? status) => status switch
    {
        null => null,
        { State: ProxyState.Running } => null,
        _ => $"; config not applied: {status.Message}",
    };

    private static IResult Invalid(string field, string message) =>
        Results.ValidationProblem(new Dictionary<string, string[]> { [field] = [message] });

    private static IResult Refused(string message) =>
        Results.Conflict(new { message });
}
