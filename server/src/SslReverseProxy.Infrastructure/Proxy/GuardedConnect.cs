using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using SslReverseProxy.Core.Security;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// An HTTP handler for requests this service makes to rule targets. It resolves the host at connect time,
/// refuses when any address it resolves to breaks the upstream policy, and dials the addresses it checked,
/// so a name that resolves elsewhere after validation cannot reach a blocked range. It follows no redirects.
/// </summary>
public static class GuardedConnect
{
    public static SocketsHttpHandler Handler(ProxyTargetValidator validator) => new()
    {
        AllowAutoRedirect = false,
        // A proxy would make the checked address the proxy's, not the target's.
        UseProxy = false,
        ConnectCallback = (context, ct) => ConnectAsync(validator, context.DnsEndPoint, ct),
    };

    public static async ValueTask<Stream> ConnectAsync(ProxyTargetValidator validator, DnsEndPoint endPoint, CancellationToken ct)
    {
        var host = endPoint.Host.Trim('[', ']');
        var addresses = await Dns.GetHostAddressesAsync(host, ct);
        if (addresses.Length == 0)
            throw new HttpRequestException($"{host} does not resolve.");
        foreach (var address in addresses)
        {
            var check = validator.CheckAddress(address);
            if (!check.Ok) throw new HttpRequestException($"{host} resolves to {address}. {check.Reason}");
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(addresses, endPoint.Port, ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
