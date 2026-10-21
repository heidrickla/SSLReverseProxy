using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Backup;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;
using SslReverseProxy.Infrastructure.Security;

namespace SslReverseProxy.Api.Endpoints;

/// <summary>Export and import of servers, rules and certificate definitions. The file holds Basic Auth hashes.</summary>
public static class BackupEndpoints
{
    public static IEndpointRouteBuilder MapBackupEndpoints(this IEndpointRouteBuilder app)
    {
        var backup = app.MapGroup("/api/backup").WithTags("Backup")
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.BackupManage));

        backup.MapGet("/", async (AppDbContext db, TimeProvider clock, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var servers = await db.Servers.AsNoTracking().Include(s => s.Rules).ToListAsync(ctx.RequestAborted);
            var certificates = await db.Certificates.AsNoTracking().ToListAsync(ctx.RequestAborted);
            var now = clock.GetUtcNow();
            await audit.AuditAsync(me, ctx, "Export Backup", "Backup", $"{servers.Count} servers",
                details: $"rules={servers.Sum(s => s.Rules.Count)} certificates={certificates.Count}");
            ctx.Response.Headers.ContentDisposition = $"attachment; filename=\"sslrp-backup-{now.UtcDateTime:yyyyMMdd-HHmmss}.json\"";
            return Results.Json(BackupFormat.Export(servers, certificates, now), BackupFormat.Json);
        });

        // Stages the import on the rows inside a change scope, reports it and keeps nothing.
        backup.MapPost("/import/dry-run", async (
            HttpContext ctx, AppDbContext db, ProxyChanges changes, IProxyController proxy, ProxyTargetValidator validator,
            IOptions<ProxyOptions> options, SecretRedactor redactor, TimeProvider clock) =>
        {
            var (req, error) = await ReadAsync(ctx);
            if (error is not null) return error;
            if (!BackupImport.TryMode(req!.Mode, out var mode)) return Invalid("mode", "Must be merge or replace.");

            using var change = await changes.EnterAsync(ctx.RequestAborted);
            var revision = await BackupImport.RevisionAsync(db, req.Document!, mode, ctx.RequestAborted);
            var stage = await BackupImport.StageAsync(db, req.Document!, mode, validator, options.Value, clock.GetUtcNow(), ctx.RequestAborted);
            ProxyPreviewDto? preview = null;
            if (stage.Problems.Count == 0)
            {
                if (BuildProblem(db, proxy, out var next) is { } buildProblem) stage.Problem("rules", buildProblem);
                else preview = ProxyEndpoints.ToDto(ConfigDiff.Compare(await proxy.GetRunningConfigJsonAsync(ctx.RequestAborted), next!, redactor));
            }
            db.ChangeTracker.Clear();
            return Results.Ok(new BackupDryRunDto(Name(mode), stage.Changes, stage.Unchanged, stage.Problems, revision, preview));
        });

        backup.MapPost("/import", async (
            HttpContext ctx, AppDbContext db, ProxyChanges changes, IProxyController proxy, ProxyTargetValidator validator,
            IOptions<ProxyOptions> options, ICertificateChecks certificates, IServerHealthStore health, IAuditLog audit,
            IEventStream events, ICurrentPrincipal me, TimeProvider clock) =>
        {
            var (req, error) = await ReadAsync(ctx);
            if (error is not null) return error;
            if (!BackupImport.TryMode(req!.Mode, out var mode)) return Invalid("mode", "Must be merge or replace.");
            if (string.IsNullOrEmpty(req.Revision)) return Invalid("revision", "Run the dry run first and send its revision.");

            var ct = ctx.RequestAborted;
            using var change = await changes.EnterAsync(ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            if (await BackupImport.RevisionAsync(db, req.Document!, mode, ct) != req.Revision)
                return Results.Problem(title: "The dry run is out of date",
                    detail: "The servers, rules or certificates changed after the dry run. Run it again.",
                    statusCode: StatusCodes.Status409Conflict);

            var now = clock.GetUtcNow();
            var stage = await BackupImport.StageAsync(db, req.Document!, mode, validator, options.Value, now, ct);
            if (stage.Problems.Count == 0 && BuildProblem(db, proxy, out _) is { } buildProblem) stage.Problem("rules", buildProblem);
            if (stage.Problems.Count > 0) return Results.ValidationProblem(stage.Problems);
            try
            {
                await db.SaveChangesAsync(ct);
            }
            catch (DbUpdateException)
            {
                return Results.Problem(title: "Conflict", detail: "The rows could not be written as staged. Run the dry run again.",
                    statusCode: StatusCodes.Status409Conflict);
            }
            await tx.CommitAsync(ct);

            // Certificate rows push when Caddy runs, as a certificate write does; rules wait for a Reload.
            var status = stage.CertificatesChanged ? await CertificateEndpoints.ApplyIfRunningAsync(db, change, ct) : null;
            if (stage.CertificatesChanged) certificates.RequestCheck();
            health.RequestCheck();
            var (added, updated, removed) = (stage.Count("add"), stage.Count("update"), stage.Count("remove"));
            await audit.AuditAsync(me, ctx, "Import Backup", "Backup", Name(mode),
                details: $"added={added} updated={updated} removed={removed} unchanged={stage.Unchanged}{CertificateEndpoints.ApplyNote(status)}");
            events.Publish(new ProxyEvent("backup.import", $"mode={Name(mode)} added={added} updated={updated} removed={removed}", now, me.Name));
            return Results.Ok(new BackupImportResultDto(added, updated, removed, stage.Unchanged, stage.RulesChanged,
                status is null ? null : ProxyEndpoints.ToDto(status)));
        });

        return app;
    }

    // The config the staged rows build, or why it cannot be built.
    private static string? BuildProblem(AppDbContext db, IProxyController proxy, out string? config)
    {
        config = null;
        var rules = BackupImport.FinalRules(db);
        if (RoutePath.Conflicts(rules).FirstOrDefault() is { } conflict) return conflict;
        try
        {
            config = proxy.BuildConfigJson(new ProxyPlan(rules, BackupImport.FinalCertificates(db).Select(CertificatePlan.From).ToList()));
            return null;
        }
        catch (InvalidOperationException ex)
        {
            return ex.Message;
        }
    }

    // Read whole and bounded, with the row counts checked on the raw JSON before it is bound.
    private static async Task<(BackupImportRequest? Request, IResult? Error)> ReadAsync(HttpContext ctx)
    {
        if (ctx.Request.ContentLength > BackupFormat.MaxBytes) return (null, TooLarge());
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await ctx.Request.Body.ReadAsync(chunk, ctx.RequestAborted)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > BackupFormat.MaxBytes) return (null, TooLarge());
        }

        JsonDocument json;
        try
        {
            json = JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = BackupFormat.Json.MaxDepth });
        }
        catch (JsonException)
        {
            return (null, Invalid("document", "The body is not JSON."));
        }
        using (json)
        {
            if (BackupFormat.CountProblem(json.RootElement) is { } tooMany) return (null, Invalid("document", tooMany));
            try
            {
                var req = json.Deserialize<BackupImportRequest>(BackupFormat.Json);
                return req?.Document is null ? (null, Invalid("document", "Required.")) : (req, null);
            }
            catch (JsonException)
            {
                return (null, Invalid("document", "The file does not match the backup format."));
            }
        }
    }

    private static string Name(BackupMode mode) => mode.ToString().ToLowerInvariant();

    private static IResult TooLarge() => Results.Problem(title: "Too large",
        detail: $"A backup is at most {BackupFormat.MaxBytes / (1024 * 1024)} MiB.", statusCode: StatusCodes.Status413PayloadTooLarge);

    private static IResult Invalid(string field, string message) =>
        Results.ValidationProblem(new Dictionary<string, string[]> { [field] = [message] });
}
