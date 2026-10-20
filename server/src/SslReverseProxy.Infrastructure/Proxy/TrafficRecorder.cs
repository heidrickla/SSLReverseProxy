namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// Turns successive scrapes of Caddy's cumulative counters into traffic since
/// the last <see cref="TakePending"/>. The controller scrapes on the sampler's
/// schedule and also just before every config load and before stopping Caddy,
/// since a changed config and a new process both restart its counters.
/// </summary>
public sealed class TrafficRecorder
{
    private readonly object _lock = new();
    private CaddyTraffic? _last;
    private CaddyTraffic? _pending;

    public void Observe(CaddyTraffic current)
    {
        lock (_lock)
        {
            // No earlier scrape since Caddy started: every count is new.
            var delta = _last is null ? current : current.Since(_last);
            _pending = _pending is null ? delta : _pending.Plus(delta);
            _last = current;
        }
    }

    /// <summary>Caddy stopped; its next run counts from zero.</summary>
    public void ProcessStopped()
    {
        lock (_lock) _last = null;
    }

    /// <summary>Traffic observed since the previous call, or null when nothing was scraped.</summary>
    public CaddyTraffic? TakePending()
    {
        lock (_lock)
        {
            var pending = _pending;
            _pending = null;
            return pending;
        }
    }
}
