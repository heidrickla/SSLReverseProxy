using System.Diagnostics;
using System.Net.Http;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Security;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// Probes an upstream for reachability. Re-applies the SSRF policy before every
/// request so this endpoint cannot be turned into an SSRF primitive (e.g. to
/// reach cloud metadata) even if a rule somehow held a disallowed target.
/// </summary>
public sealed class UpstreamHealthChecker : IUpstreamHealthChecker
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly ProxyTargetValidator _validator;

    public UpstreamHealthChecker(IHttpClientFactory httpFactory, ProxyTargetValidator validator)
    {
        _httpFactory = httpFactory;
        _validator = validator;
    }

    public async Task<UpstreamHealth> CheckAsync(string upstreamUrl, CancellationToken ct = default)
    {
        var check = _validator.ValidateUpstream(upstreamUrl);
        if (!check.Ok)
            return new UpstreamHealth(false, null, null, check.Reason);

        var client = _httpFactory.CreateClient("upstream-health");
        client.Timeout = TimeSpan.FromSeconds(5);

        var sw = Stopwatch.StartNew();
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Head, upstreamUrl);
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            sw.Stop();
            return new UpstreamHealth(true, (int)resp.StatusCode, sw.ElapsedMilliseconds, null);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new UpstreamHealth(false, null, sw.ElapsedMilliseconds, ex.Message);
        }
    }
}
