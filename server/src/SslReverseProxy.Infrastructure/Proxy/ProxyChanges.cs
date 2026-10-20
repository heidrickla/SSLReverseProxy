using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// The one way to change what Caddy holds. Its config is built from rules, certificate rows and renewal
/// marks; every decision over those rows that a push depends on, and every start, stop and push, runs in a
/// scope, one scope at a time. Each scope reads the rows it decides on after entering, so a pushed config
/// matches the rows as they stand when it is pushed.
/// </summary>
public sealed class ProxyChanges(IProxyController proxy)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    // Caddy may hold a renewal policy no row wants: the push that would have removed it was refused.
    private bool _policyStale;

    public async Task<Scope> EnterAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        return new Scope(this);
    }

    public sealed class Scope : IDisposable
    {
        private ProxyChanges? _owner;

        internal Scope(ProxyChanges owner) => _owner = owner;

        private ProxyChanges Owner => _owner ?? throw new ObjectDisposedException(nameof(Scope));

        /// <summary>Caddy may hold a renewal policy that no row wants. Any config Caddy takes removes it.</summary>
        public bool PolicyStale => Owner._policyStale;

        public Task<ProxyStatus> StatusAsync(CancellationToken ct) => Owner.Proxy.GetStatusAsync(ct);

        /// <summary>Pushes a plan; load it from the rows inside this scope. A refused push leaves Caddy's config as it was.</summary>
        public async Task<ProxyStatus> ApplyAsync(ProxyPlan plan, CancellationToken ct) =>
            Taken(await Owner.Proxy.ApplyConfigurationAsync(plan, ct));

        /// <summary>Pushes a snapshot's config, which holds no renewal policy.</summary>
        public async Task<ProxyStatus> ApplyRawAsync(string configJson, CancellationToken ct) =>
            Taken(await Owner.Proxy.ApplyRawConfigAsync(configJson, ct));

        public async Task<ProxyStatus> StartAsync(CancellationToken ct) => Taken(await Owner.Proxy.StartAsync(ct));

        public async Task<ProxyStatus> StopAsync(CancellationToken ct)
        {
            var status = await Owner.Proxy.StopAsync(ct);
            if (status.State == ProxyState.Stopped) Owner._policyStale = false;
            return status;
        }

        /// <summary>Records that Caddy refused the push meant to remove a renewal policy.</summary>
        public void PolicyLeftBehind() => Owner._policyStale = true;

        // A plan pushed in a scope carries only the policies the rows want, and a snapshot or a new process none.
        private ProxyStatus Taken(ProxyStatus status)
        {
            if (status.State == ProxyState.Running) Owner._policyStale = false;
            return status;
        }

        public void Dispose() => Interlocked.Exchange(ref _owner, null)?._gate.Release();
    }

    private IProxyController Proxy => proxy;
}
