using System.Collections.Concurrent;
using System.Threading.Channels;
using SslReverseProxy.Core.Abstractions;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// In-process fan-out of control-plane events to any number of SSE subscribers.
/// Each subscriber gets a bounded channel; slow consumers drop oldest events
/// rather than blocking publishers.
/// </summary>
public sealed class EventStream : IEventStream
{
    private readonly ConcurrentDictionary<Guid, Channel<ProxyEvent>> _subscribers = new();

    public void Publish(ProxyEvent evt)
    {
        foreach (var channel in _subscribers.Values)
            channel.Writer.TryWrite(evt);
    }

    public async IAsyncEnumerable<ProxyEvent> Subscribe(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var id = Guid.NewGuid();
        var channel = Channel.CreateBounded<ProxyEvent>(new BoundedChannelOptions(100)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });
        _subscribers[id] = channel;
        try
        {
            await foreach (var evt in channel.Reader.ReadAllAsync(ct))
                yield return evt;
        }
        finally
        {
            _subscribers.TryRemove(id, out _);
        }
    }
}
