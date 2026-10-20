using System.Collections.Concurrent;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Api.Alerts;

/// <summary>
/// Turns server health readings into down and up alerts. A server is down after <c>downChecks</c>
/// consecutive Error readings and up at the first Active reading after that. Inactive (no enabled
/// upstreams) ends a down state without an alert. State is in memory, so a server still down after
/// a restart alerts again.
/// </summary>
public sealed class ServerAlertTracker(int downChecks)
{
    private readonly int _downChecks = Math.Max(1, downChecks);
    private readonly ConcurrentDictionary<Guid, (int Failing, bool Down)> _state = new();

    public Alert? Observe(Guid serverId, string name, ServerHealth health, DateTimeOffset now)
    {
        var (failing, down) = _state.GetValueOrDefault(serverId);
        Alert? alert = null;
        switch (health.Status)
        {
            case ServerHealthStatus.Error:
                failing++;
                if (!down && failing >= _downChecks)
                {
                    down = true;
                    alert = new Alert(AlertTypes.ServerDown, AlertSeverity.Critical, name, $"Server down: {name}",
                        $"{health.UpstreamsTotal - health.UpstreamsUp} of {health.UpstreamsTotal} upstreams of {name} do not answer.", now);
                }
                break;
            case ServerHealthStatus.Active:
                if (down)
                    alert = new Alert(AlertTypes.ServerUp, AlertSeverity.Info, name, $"Server up: {name}",
                        $"All {health.UpstreamsTotal} upstreams of {name} answer.", now);
                (failing, down) = (0, false);
                break;
            default:
                // Inactive or unknown: no reading either way, so a down server stays down until Active.
                failing = 0;
                break;
        }
        _state[serverId] = (failing, down);
        return alert;
    }

    public void Forget(Guid serverId) => _state.TryRemove(serverId, out _);
}
