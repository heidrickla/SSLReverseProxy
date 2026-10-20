using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>The leaf certificate Caddy served for a name.</summary>
/// <param name="MatchesName">The certificate covers the name asked for; Caddy can answer with another one.</param>
public sealed record ServedCertificate(
    string Serial, DateTimeOffset NotBefore, DateTimeOffset NotAfter, string Issuer, string Algorithm, bool MatchesName);

public interface ICertificateProbe
{
    /// <summary>The certificate served for <paramref name="domain"/>, or null when the handshake fails.</summary>
    Task<ServedCertificate?> ReadAsync(string domain, CancellationToken ct);
}

/// <summary>
/// Reads the certificate Caddy serves by handshaking with its HTTPS listener on loopback with the name
/// as SNI. That is the certificate clients get, whether it is the name's own, a wildcard covering it,
/// or a multi-name one, which Caddy's storage layout does not say. A wildcard row is asked about with
/// <see cref="CertificateNames.ProbeHost"/>.
/// </summary>
public sealed class TlsCertificateProbe : ICertificateProbe
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);
    private readonly ProxyOptions _options;

    public TlsCertificateProbe(IOptions<ProxyOptions> options) => _options = options.Value;

    public async Task<ServedCertificate?> ReadAsync(string domain, CancellationToken ct)
    {
        var host = CertificateNames.ProbeHost(domain);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Timeout);
        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, _options.HttpsPort, timeout.Token);
            await using var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                // Reading, not trusting: an internal-CA or not-yet-valid certificate is still the one served.
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            }, timeout.Token);
            return tls.RemoteCertificate is { } served ? Describe(served, host) : null;
        }
        catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException
                                   || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return null;
        }
    }

    public static ServedCertificate Describe(X509Certificate served, string host)
    {
        using var cert = X509CertificateLoader.LoadCertificate(served.GetRawCertData());
        return new ServedCertificate(
            cert.SerialNumber,
            new DateTimeOffset(cert.NotBefore.ToUniversalTime(), TimeSpan.Zero),
            new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero),
            IssuerName(cert),
            Algorithm(cert),
            cert.MatchesHostname(host));
    }

    private static string IssuerName(X509Certificate2 cert)
    {
        string? org = null, cn = null;
        foreach (var rdn in cert.IssuerName.EnumerateRelativeDistinguishedNames())
        {
            var oid = rdn.GetSingleElementType().Value;
            if (oid == "2.5.4.10") org ??= rdn.GetSingleElementValue();
            else if (oid == "2.5.4.3") cn ??= rdn.GetSingleElementValue();
        }
        return string.Join(" ", new[] { org, cn }.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct());
    }

    private static string Algorithm(X509Certificate2 cert)
    {
        using var ec = cert.GetECDsaPublicKey();
        if (ec is not null) return $"ECDSA {ec.KeySize}";
        using var rsa = cert.GetRSAPublicKey();
        if (rsa is not null) return $"RSA {rsa.KeySize}";
        return cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "unknown";
    }
}
