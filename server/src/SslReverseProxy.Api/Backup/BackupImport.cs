using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Api.Endpoints;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;

namespace SslReverseProxy.Api.Backup;

public enum BackupMode { Merge, Replace }

public static partial class BackupFormat
{
    public const int Version = 1;
    public const int MaxBytes = 2 * 1024 * 1024;
    public const int MaxServers = 500;
    public const int MaxRules = 5000;
    public const int MaxCertificates = 2000;
    public const string Masked = "[masked]";

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { MaxDepth = 32 };

    [GeneratedRegex(@"^\$2[abxy]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$")]
    public static partial Regex Bcrypt();

    public static BackupDocument Export(IEnumerable<ProxyServer> servers, IEnumerable<Certificate> certificates, DateTimeOffset at) => new(
        Version, at,
        servers.OrderBy(s => s.Name, StringComparer.Ordinal).ThenBy(s => s.Id)
            .Select(s => new BackupServer(s.Id, s.Name, s.Host, s.Os, s.Rules
                .OrderBy(r => RoutePath.RouteKey(r.Domain, r.PathPrefix), StringComparer.Ordinal).ThenBy(r => r.Id)
                .Select(ToBackup).ToList()))
            .ToList(),
        certificates.OrderBy(c => c.Domain, StringComparer.Ordinal)
            .Select(c => new BackupCertificate(c.Id, c.Domain, c.Source.ToString(), c.Challenge.ToString())).ToList());

    public static BackupRule ToBackup(ProxyRule r) => new(
        r.Id, r.Domain, r.UpstreamUrl, r.EnableTls, r.Enabled, r.AllowedCidrs, r.DeniedCidrs, r.RateLimitPerMinute,
        r.BasicAuthUsername, r.BasicAuthPasswordHash,
        new RuleHardeningRequest
        {
            AdditionalUpstreams = r.AdditionalUpstreams,
            LoadBalancePolicy = r.LoadBalancePolicy,
            DialTimeoutSeconds = r.DialTimeoutSeconds,
            UpstreamReadTimeoutSeconds = r.UpstreamReadTimeoutSeconds,
            UpstreamWriteTimeoutSeconds = r.UpstreamWriteTimeoutSeconds,
            UpstreamTlsServerName = r.UpstreamTlsServerName,
            UpstreamTlsTrustedCaFile = r.UpstreamTlsTrustedCaFile,
            UpstreamTlsInsecureSkipVerify = r.UpstreamTlsInsecureSkipVerify,
            MaxRequestBodyBytes = r.MaxRequestBodyBytes,
            EnableSecurityHeaders = r.EnableSecurityHeaders,
            HstsMaxAgeDays = r.HstsMaxAgeDays,
            HstsIncludeSubdomains = r.HstsIncludeSubdomains,
            FrameOptions = r.FrameOptions,
            HealthCheckPath = r.HealthCheckPath,
            HealthCheckIntervalSeconds = r.HealthCheckIntervalSeconds,
            HealthCheckTimeoutSeconds = r.HealthCheckTimeoutSeconds,
            HealthCheckExpectStatus = r.HealthCheckExpectStatus,
            SkipAccessLog = r.SkipAccessLog,
        },
        new RuleRoutingRequest { PathPrefix = r.PathPrefix, StripPathPrefix = r.StripPathPrefix },
        r.SignInProvider is null ? null : new RuleSignInRequest
        {
            Provider = r.SignInProvider,
            VerifierUrl = r.SignInVerifierUrl,
            TeamDomain = r.CloudflareTeamDomain,
            Audience = r.CloudflareAudience,
        });

    /// <summary>The row-count limits, read from the raw JSON before anything is bound to it.</summary>
    public static string? CountProblem(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object || Prop(root, "document") is not { ValueKind: JsonValueKind.Object } doc)
            return "The body needs a document object.";
        var servers = Prop(doc, "servers") is { ValueKind: JsonValueKind.Array } s ? s : default;
        var certificates = Prop(doc, "certificates") is { ValueKind: JsonValueKind.Array } c ? c : default;
        var serverCount = servers.ValueKind == JsonValueKind.Array ? servers.GetArrayLength() : 0;
        if (serverCount > MaxServers) return $"At most {MaxServers} servers.";
        var ruleCount = servers.ValueKind != JsonValueKind.Array ? 0 : servers.EnumerateArray()
            .Sum(e => e.ValueKind == JsonValueKind.Object && Prop(e, "rules") is { ValueKind: JsonValueKind.Array } r ? r.GetArrayLength() : 0);
        if (ruleCount > MaxRules) return $"At most {MaxRules} rules.";
        if (certificates.ValueKind == JsonValueKind.Array && certificates.GetArrayLength() > MaxCertificates)
            return $"At most {MaxCertificates} certificates.";
        return null;
    }

    // Binding is case-insensitive, so the limits are too.
    private static JsonElement? Prop(JsonElement obj, string name)
    {
        foreach (var p in obj.EnumerateObject())
            if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) return p.Value;
        return null;
    }
}

/// <summary>What an import would do, staged on tracked rows. The dry run discards it; the import saves it.</summary>
public sealed class BackupStage
{
    public List<BackupChangeDto> Changes { get; } = [];
    public Dictionary<string, string[]> Problems { get; } = new(StringComparer.Ordinal);
    public int Unchanged { get; set; }
    public bool RulesChanged { get; set; }
    public bool CertificatesChanged { get; set; }

    public int Count(string action) => Changes.Count(c => c.Action == action);

    public void Problem(string key, string message) =>
        Problems[key] = Problems.TryGetValue(key, out var existing) ? [.. existing, message] : [message];
}

public static class BackupImport
{
    public static bool TryMode(string? value, out BackupMode mode)
    {
        mode = BackupMode.Merge;
        if (string.IsNullOrWhiteSpace(value) || value.Equals("merge", StringComparison.OrdinalIgnoreCase)) return true;
        if (!value.Equals("replace", StringComparison.OrdinalIgnoreCase)) return false;
        mode = BackupMode.Replace;
        return true;
    }

    /// <summary>Names the rows as they stand, the document and the mode, so an import refuses when any moved after its dry run.</summary>
    public static async Task<string> RevisionAsync(AppDbContext db, BackupDocument doc, BackupMode mode, CancellationToken ct)
    {
        var servers = await db.Servers.AsNoTracking().Include(s => s.Rules).ToListAsync(ct);
        var certificates = await db.Certificates.AsNoTracking().ToListAsync(ct);
        var current = JsonSerializer.Serialize(BackupFormat.Export(servers, certificates, DateTimeOffset.UnixEpoch), BackupFormat.Json);
        var incoming = JsonSerializer.Serialize(doc, BackupFormat.Json);
        var framed = $"{current.Length}:{current}\n{mode}\n{incoming}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(framed)));
    }

    public static List<ProxyRule> FinalRules(AppDbContext db) => Live<ProxyRule>(db);

    public static List<Certificate> FinalCertificates(AppDbContext db) => Live<Certificate>(db);

    private static List<T> Live<T>(AppDbContext db) where T : class =>
        db.ChangeTracker.Entries<T>().Where(e => e.State is not (EntityState.Deleted or EntityState.Detached)).Select(e => e.Entity).ToList();

    /// <summary>
    /// Applies the document to the tracked rows. Servers match by id, then name; rules by id, then host and
    /// path; certificates by id, then domain. A rule passes every check a rule write runs, against the whole
    /// set the import leaves.
    /// </summary>
    public static async Task<BackupStage> StageAsync(
        AppDbContext db, BackupDocument doc, BackupMode mode, ProxyTargetValidator validator, ProxyOptions options,
        DateTimeOffset now, CancellationToken ct)
    {
        var stage = new BackupStage();
        if (!CheckShape(doc, stage)) return stage;

        var servers = await db.Servers.Include(s => s.Rules).ToListAsync(ct);
        var certificates = await db.Certificates.ToListAsync(ct);
        var serverFor = StageServers(db, doc.Servers!, servers, validator, stage, now, out var claimed);
        StageRules(db, doc.Servers!, mode, servers, serverFor, validator, stage, now);
        // After the rules: removing a tracked server deletes the rules it holds then, so a rule moving off it moves first.
        if (mode == BackupMode.Replace)
        {
            foreach (var server in servers.Where(s => !claimed.Contains(s.Id)))
            {
                db.Servers.Remove(server);
                stage.Changes.Add(new BackupChangeDto("server", "remove", server.Id, server.Name, []));
            }
        }
        StageCertificates(db, doc.Certificates!, mode, certificates, options, stage);
        return stage;
    }

    private static bool CheckShape(BackupDocument doc, BackupStage stage)
    {
        if (doc.FormatVersion != BackupFormat.Version)
        {
            stage.Problem("formatVersion", $"This file is format {doc.FormatVersion}; this build reads format {BackupFormat.Version}.");
            return false;
        }
        if (doc.Servers is null) stage.Problem("servers", "Required.");
        if (doc.Certificates is null) stage.Problem("certificates", "Required.");
        if (stage.Problems.Count > 0) return false;

        var serverIds = new HashSet<Guid>();
        var serverNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ruleIds = new HashSet<Guid>();
        for (var i = 0; i < doc.Servers!.Count; i++)
        {
            var s = doc.Servers[i];
            if (s is null) { stage.Problem($"servers[{i}]", "Required."); continue; }
            if (s.Id == Guid.Empty) stage.Problem($"servers[{i}].id", "Required.");
            else if (!serverIds.Add(s.Id)) stage.Problem($"servers[{i}].id", "Another server in the file has this id.");
            if (!string.IsNullOrWhiteSpace(s.Name) && !serverNames.Add(s.Name.Trim()))
                stage.Problem($"servers[{i}].name", "Another server in the file has this name.");
            if (s.Rules is null) { stage.Problem($"servers[{i}].rules", "Required."); continue; }
            for (var j = 0; j < s.Rules.Count; j++)
            {
                var r = s.Rules[j];
                if (r is null) stage.Problem($"servers[{i}].rules[{j}]", "Required.");
                else if (r.Id == Guid.Empty) stage.Problem($"servers[{i}].rules[{j}].id", "Required.");
                else if (!ruleIds.Add(r.Id)) stage.Problem($"servers[{i}].rules[{j}].id", "Another rule in the file has this id.");
            }
        }

        var certificateIds = new HashSet<Guid>();
        var domains = new HashSet<string>(StringComparer.Ordinal);
        for (var k = 0; k < doc.Certificates!.Count; k++)
        {
            var c = doc.Certificates[k];
            if (c is null) { stage.Problem($"certificates[{k}]", "Required."); continue; }
            if (c.Id == Guid.Empty) stage.Problem($"certificates[{k}].id", "Required.");
            else if (!certificateIds.Add(c.Id)) stage.Problem($"certificates[{k}].id", "Another certificate in the file has this id.");
            if (!string.IsNullOrWhiteSpace(c.Domain) && !domains.Add(CertificateNames.Normalize(c.Domain)))
                stage.Problem($"certificates[{k}].domain", "Another certificate in the file has this domain.");
        }
        return stage.Problems.Count == 0;
    }

    private static Dictionary<int, ProxyServer> StageServers(
        AppDbContext db, IReadOnlyList<BackupServer> incoming, List<ProxyServer> servers,
        ProxyTargetValidator validator, BackupStage stage, DateTimeOffset now, out HashSet<Guid> claimed)
    {
        var matched = Match(incoming, servers, s => s.Id, s => s.Id, (d, s) => Same(d.Name, s.Name),
            i => $"servers[{i}].name", d => $"More than one server is named '{d.Name}'.", stage);
        claimed = matched.Values.Select(s => s.Id).ToHashSet();
        var staged = new Dictionary<int, ProxyServer>();
        for (var i = 0; i < incoming.Count; i++)
        {
            var d = incoming[i];
            var at = $"servers[{i}]";
            var name = d.Name?.Trim() ?? string.Empty;
            var host = d.Host?.Trim() ?? string.Empty;
            if (name.Length is 0 or > 200) stage.Problem($"{at}.name", "Required, at most 200 characters.");
            var hostCheck = validator.ValidateDomain(host);
            if (!hostCheck.Ok && !System.Net.IPAddress.TryParse(host, out _))
                stage.Problem($"{at}.host", hostCheck.Reason ?? "Invalid host.");
            if (d.Os is not ("linux" or "windows")) stage.Problem($"{at}.os", "Must be linux or windows.");
            if (stage.Problems.Keys.Any(k => k.StartsWith(at + ".", StringComparison.Ordinal) && !k.StartsWith(at + ".rules", StringComparison.Ordinal)))
                continue;

            if (matched.TryGetValue(i, out var server))
            {
                var fields = new List<BackupFieldDto>();
                Field(fields, "name", server.Name, name);
                Field(fields, "host", server.Host, host);
                Field(fields, "os", server.Os, d.Os);
                server.Name = name;
                server.Host = host;
                server.Os = d.Os!;
                Record(stage, "server", server.Id, name, fields);
            }
            else
            {
                server = new ProxyServer { Id = d.Id, Name = name, Host = host, Os = d.Os!, CreatedAt = now };
                db.Servers.Add(server);
                stage.Changes.Add(new BackupChangeDto("server", "add", server.Id, name, []));
            }
            staged[i] = server;
        }
        return staged;
    }

    private static void StageRules(
        AppDbContext db, IReadOnlyList<BackupServer> incoming, BackupMode mode, List<ProxyServer> servers,
        Dictionary<int, ProxyServer> serverFor, ProxyTargetValidator validator, BackupStage stage, DateTimeOffset now)
    {
        var existing = servers.SelectMany(s => s.Rules).ToList();
        var flat = incoming.SelectMany((s, i) => s.Rules!.Select((r, j) => (Rule: r, At: $"servers[{i}].rules[{j}]", Server: i))).ToList();
        var matched = Match(flat, existing, f => f.Rule.Id, r => r.Id,
            (f, r) => RoutePath.TryNormalize(f.Rule.Routing?.PathPrefix, out var prefix, out _)
                && RoutePath.RouteKey(f.Rule.Domain ?? string.Empty, prefix) == RoutePath.RouteKey(r.Domain, r.PathPrefix),
            i => $"{flat[i].At}.domain", f => $"More than one rule serves '{f.Rule.Domain}{f.Rule.Routing?.PathPrefix}'; give this one its id from the export.",
            stage);
        var names = servers.ToDictionary(s => s.Id, s => s.Name);
        foreach (var s in serverFor.Values) names[s.Id] = s.Name;

        var staged = new List<(ProxyRule Rule, string At)>();
        for (var n = 0; n < flat.Count; n++)
        {
            var (d, at, i) = flat[n];
            if (!serverFor.TryGetValue(i, out var server)) continue;

            var errors = ServerEndpoints.RuleErrors(d.Domain ?? string.Empty, d.UpstreamUrl ?? string.Empty, validator,
                d.AllowedCidrs, d.DeniedCidrs, d.RateLimitPerMinute, d.BasicAuthUsername, basicAuthPassword: null,
                d.Hardening ?? new RuleHardeningRequest(), d.Routing ?? new RuleRoutingRequest(), d.SignIn,
                existingAdditionalUpstreams: null, isCreate: false);
            var user = string.IsNullOrWhiteSpace(d.BasicAuthUsername) ? null : d.BasicAuthUsername.Trim();
            if (user is not null && string.IsNullOrEmpty(d.BasicAuthPasswordHash))
                errors["basicAuthPasswordHash"] = ["A Basic Auth username needs its password hash."];
            else if (user is not null && !BackupFormat.Bcrypt().IsMatch(d.BasicAuthPasswordHash!))
                errors["basicAuthPasswordHash"] = ["Not a bcrypt hash."];
            else if (user is null && !string.IsNullOrEmpty(d.BasicAuthPasswordHash))
                errors["basicAuthUsername"] = ["A password hash needs a Basic Auth username."];
            foreach (var (key, messages) in errors)
                foreach (var m in messages) stage.Problem($"{at}.{key}", m);
            if (errors.Count > 0) continue;

            var rule = matched.TryGetValue(n, out var row) ? row : new ProxyRule { Id = d.Id, CreatedAt = now, UpdatedAt = now };
            var before = row is null ? null : Flatten(BackupFormat.ToBackup(row));
            var fromServer = row?.ServerId;
            Apply(d, rule, server.Id);
            foreach (var field in rule.PlaceholderFields())
                stage.Problem($"{at}.{char.ToLowerInvariant(field[0])}{field[1..]}", "Must not contain '{' or '}'.");

            var name = $"{rule.Domain}{rule.PathPrefix} on {server.Name}";
            if (row is null)
            {
                db.Rules.Add(rule);
                stage.Changes.Add(new BackupChangeDto("rule", "add", rule.Id, name, []));
                stage.RulesChanged = true;
            }
            else
            {
                var fields = Diff(before!, Flatten(BackupFormat.ToBackup(rule)));
                if (fromServer != server.Id)
                    fields.Insert(0, new BackupFieldDto("server", Quote(names.GetValueOrDefault(fromServer!.Value)), Quote(server.Name)));
                if (fields.Count > 0)
                {
                    rule.Version++;
                    rule.UpdatedAt = now;
                    stage.RulesChanged = true;
                }
                Record(stage, "rule", rule.Id, name, fields);
            }
            staged.Add((rule, at));
        }

        if (mode == BackupMode.Replace)
        {
            var kept = matched.Values.Select(r => r.Id).ToHashSet();
            foreach (var rule in existing.Where(r => !kept.Contains(r.Id)))
            {
                db.Rules.Remove(rule);
                stage.Changes.Add(new BackupChangeDto("rule", "remove", rule.Id, $"{rule.Domain}{rule.PathPrefix} on {names.GetValueOrDefault(rule.ServerId)}", []));
                stage.RulesChanged = true;
            }
        }

        // Against every rule the import leaves, so two rows of the file and a row it keeps are all checked.
        var final = FinalRules(db);
        foreach (var (rule, at) in staged)
            if (RoutePath.ConflictWith(rule, final) is { } clash) stage.Problem($"{at}.domain", clash);
    }

    private static void StageCertificates(
        AppDbContext db, IReadOnlyList<BackupCertificate> incoming, BackupMode mode, List<Certificate> certificates,
        ProxyOptions options, BackupStage stage)
    {
        var tlsHosts = FinalRules(db).Where(r => r.EnableTls).Select(r => CertificateNames.Normalize(r.Domain)).ToHashSet(StringComparer.Ordinal);
        var matched = Match(incoming, certificates, c => c.Id, c => c.Id,
            (d, c) => c.Domain == CertificateNames.Normalize(d.Domain ?? string.Empty),
            k => $"certificates[{k}].domain", d => $"More than one row holds '{d.Domain}'.", stage);
        for (var k = 0; k < incoming.Count; k++)
        {
            var d = incoming[k];
            var at = $"certificates[{k}]";
            var domain = CertificateNames.Normalize(d.Domain ?? string.Empty);
            var problems = stage.Problems.Count;
            if (CertificateNames.Problem(d.Domain) is { } nameProblem) stage.Problem($"{at}.domain", nameProblem);
            if (!Enum.TryParse<CertificateSource>(d.Source, ignoreCase: true, out var source) || !Enum.IsDefined(source) || int.TryParse(d.Source, out _))
                stage.Problem($"{at}.source", "Must be Manual or Rule.");
            else if (source == CertificateSource.Rule && !tlsHosts.Contains(domain))
                stage.Problem($"{at}.source", "No TLS rule the import leaves names this host.");
            if (!CertificateEndpoints.TryChallenge(d.Challenge, out var challenge))
                stage.Problem($"{at}.challenge", "Challenge must be Http or DnsCloudflare.");
            else if (CertificateNames.Problem(d.Domain) is null && CertificateEndpoints.ChallengeProblem(domain, challenge, options) is { } challengeProblem)
                stage.Problem($"{at}.challenge", challengeProblem);
            if (matched.TryGetValue(k, out var row) && row.Domain != domain)
                stage.Problem($"{at}.id", $"This id belongs to {row.Domain}.");
            if (stage.Problems.Count > problems) continue;

            if (row is not null)
            {
                var fields = new List<BackupFieldDto>();
                Field(fields, "source", row.Source.ToString(), source.ToString());
                Field(fields, "challenge", row.Challenge.ToString(), challenge.ToString());
                row.Source = source;
                row.Challenge = challenge;
                if (fields.Count > 0) stage.CertificatesChanged = true;
                Record(stage, "certificate", row.Id, domain, fields);
            }
            else
            {
                db.Certificates.Add(new Certificate
                {
                    Id = d.Id, Domain = domain, Source = source, Challenge = challenge,
                    Status = CertificateStatus.Issuing, Issuer = string.Empty,
                });
                stage.Changes.Add(new BackupChangeDto("certificate", "add", d.Id, domain, []));
                stage.CertificatesChanged = true;
            }
        }

        // A rule host's row follows its rules, so replace removes only names registered by hand.
        if (mode == BackupMode.Replace)
        {
            var kept = matched.Values.Select(c => c.Id).ToHashSet();
            foreach (var row in certificates.Where(c => c.Source == CertificateSource.Manual && !kept.Contains(c.Id)))
            {
                db.Certificates.Remove(row);
                stage.Changes.Add(new BackupChangeDto("certificate", "remove", row.Id, row.Domain, []));
                stage.CertificatesChanged = true;
            }
        }
    }

    // By id first; then each unmatched entry by its natural key among the rows no entry claimed.
    private static Dictionary<int, TRow> Match<TIn, TRow>(
        IReadOnlyList<TIn> incoming, IReadOnlyList<TRow> rows, Func<TIn, Guid> incomingId, Func<TRow, Guid> rowId,
        Func<TIn, TRow, bool> sameKey, Func<int, string> problemAt, Func<TIn, string> ambiguous, BackupStage stage)
    {
        var byId = rows.ToDictionary(rowId);
        var matched = new Dictionary<int, TRow>();
        var claimed = new HashSet<Guid>();
        for (var i = 0; i < incoming.Count; i++)
            if (byId.TryGetValue(incomingId(incoming[i]), out var row)) { matched[i] = row; claimed.Add(rowId(row)); }
        for (var i = 0; i < incoming.Count; i++)
        {
            if (matched.ContainsKey(i)) continue;
            var candidates = rows.Where(r => !claimed.Contains(rowId(r)) && sameKey(incoming[i], r)).ToList();
            if (candidates.Count > 1) stage.Problem(problemAt(i), ambiguous(incoming[i]));
            else if (candidates.Count == 1) { matched[i] = candidates[0]; claimed.Add(rowId(candidates[0])); }
        }
        return matched;
    }

    private static void Apply(BackupRule d, ProxyRule rule, Guid serverId)
    {
        rule.ServerId = serverId;
        rule.Domain = d.Domain!.Trim();
        rule.UpstreamUrl = d.UpstreamUrl!.Trim();
        rule.EnableTls = d.EnableTls;
        rule.Enabled = d.Enabled;
        rule.AllowedCidrs = ServerEndpoints.NormalizeCsv(d.AllowedCidrs);
        rule.DeniedCidrs = ServerEndpoints.NormalizeCsv(d.DeniedCidrs);
        rule.RateLimitPerMinute = d.RateLimitPerMinute is > 0 ? d.RateLimitPerMinute : null;
        rule.BasicAuthUsername = string.IsNullOrWhiteSpace(d.BasicAuthUsername) ? null : d.BasicAuthUsername.Trim();
        rule.BasicAuthPasswordHash = rule.BasicAuthUsername is null ? null : d.BasicAuthPasswordHash;
        ServerEndpoints.ApplyHardening(rule, d.Hardening ?? new RuleHardeningRequest());
        ServerEndpoints.ApplyRouting(rule, d.Routing ?? new RuleRoutingRequest());
        // A backup row is the whole rule, so no sign-in block means none.
        ServerEndpoints.ApplySignIn(rule, d.SignIn ?? new RuleSignInRequest());
    }

    private static void Record(BackupStage stage, string kind, Guid id, string name, List<BackupFieldDto> fields)
    {
        if (fields.Count == 0) stage.Unchanged++;
        else stage.Changes.Add(new BackupChangeDto(kind, "update", id, name, fields));
    }

    private static void Field(List<BackupFieldDto> fields, string field, string? before, string? after)
    {
        if (!string.Equals(before, after, StringComparison.Ordinal)) fields.Add(new BackupFieldDto(field, Quote(before), Quote(after)));
    }

    private static string? Quote(string? value) => value is null ? null : JsonValue.Create(value).ToJsonString();

    private static Dictionary<string, JsonNode?> Flatten(BackupRule rule)
    {
        var flat = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        void Walk(JsonObject obj, string prefix)
        {
            foreach (var (key, value) in obj)
            {
                if (prefix.Length == 0 && key == "id") continue;
                if (value is JsonObject child) Walk(child, $"{prefix}{key}.");
                else flat[$"{prefix}{key}"] = value?.DeepClone();
            }
        }
        Walk(JsonSerializer.SerializeToNode(rule, BackupFormat.Json)!.AsObject(), "");
        return flat;
    }

    private static List<BackupFieldDto> Diff(Dictionary<string, JsonNode?> before, Dictionary<string, JsonNode?> after)
    {
        var fields = new List<BackupFieldDto>();
        foreach (var key in before.Keys.Concat(after.Keys.Where(k => !before.ContainsKey(k))))
        {
            var b = before.GetValueOrDefault(key);
            var a = after.GetValueOrDefault(key);
            if (JsonNode.DeepEquals(b, a)) continue;
            var hash = key == "basicAuthPasswordHash";
            fields.Add(new BackupFieldDto(key,
                b is null ? null : hash ? BackupFormat.Masked : b.ToJsonString(),
                a is null ? null : hash ? BackupFormat.Masked : a.ToJsonString()));
        }
        return fields;
    }

    private static bool Same(string? a, string? b) =>
        string.Equals(a?.Trim(), b?.Trim(), StringComparison.OrdinalIgnoreCase);
}
