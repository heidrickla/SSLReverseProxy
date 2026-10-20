using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Alerts;

public sealed record AlertDelivery(string Target, bool Delivered, int? Status, string? Error, int Attempts);

/// <summary>The HTTP request each target kind takes.</summary>
public static class AlertRequests
{
    public static HttpRequestMessage Build(AlertTarget target, Alert alert)
    {
        if (target.Url is not { } url) throw new InvalidOperationException("The target has no usable URL.");

        var request = target.Kind == AlertTarget.Ntfy
            // JSON publishing goes to the server root with the topic in the body, so titles may hold any character.
            ? new HttpRequestMessage(HttpMethod.Post, new Uri(url, "."))
            {
                Content = JsonContent.Create(new JsonObject
                {
                    ["topic"] = url.Segments[^1],
                    ["title"] = alert.Title,
                    ["message"] = alert.Message,
                    ["priority"] = alert.Severity switch { AlertSeverity.Critical => 5, AlertSeverity.Warning => 4, _ => 3 },
                    ["tags"] = new JsonArray(NtfyTag(alert)),
                }),
            }
            : new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = JsonContent.Create(new JsonObject
                {
                    ["type"] = alert.Type,
                    ["severity"] = alert.Severity.ToString().ToLowerInvariant(),
                    ["subject"] = alert.Subject,
                    ["title"] = alert.Title,
                    ["message"] = alert.Message,
                    ["at"] = alert.At.ToString("O"),
                }),
            };

        if (target.Token is { } token)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private static string NtfyTag(Alert alert) => alert switch
    {
        { Type: AlertTypes.ServerUp } => "white_check_mark",
        { Severity: AlertSeverity.Critical } => "rotating_light",
        { Severity: AlertSeverity.Warning } => "warning",
        _ => "information_source",
    };
}

/// <summary>
/// Sends one alert to one target: up to three tries, retrying network errors, timeouts, 408, 429 and 5xx.
/// Logs carry the target's name, the status and an error class only, never the URL or token.
/// </summary>
public sealed class AlertSender(IHttpClientFactory http, TimeProvider clock, ILogger<AlertSender> logger)
{
    public const string ClientName = "alerts";
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);
    internal static readonly TimeSpan[] Backoff = [TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(10)];

    public async Task<AlertDelivery> SendAsync(AlertTarget target, Alert alert, CancellationToken ct)
    {
        if (!target.Usable) return new AlertDelivery(target.Name, false, null, target.Problem, 0);

        var client = http.CreateClient(ClientName);
        for (var attempt = 1; ; attempt++)
        {
            int? status = null;
            string error;
            bool retry;
            try
            {
                using var request = AlertRequests.Build(target, alert);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                status = (int)response.StatusCode;
                if (response.IsSuccessStatusCode)
                {
                    logger.LogInformation("Alert {Type} for {Subject} sent to {Target}: HTTP {Status}.",
                        alert.Type, alert.Subject, target.Name, status);
                    return new AlertDelivery(target.Name, true, status, null, attempt);
                }
                error = $"HTTP {status}";
                retry = status is >= 500 or 408 or 429;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                error = "timed out";
                retry = true;
            }
            catch (HttpRequestException ex)
            {
                error = ex.HttpRequestError switch
                {
                    HttpRequestError.NameResolutionError => "name not resolved",
                    HttpRequestError.ConnectionError => "connection failed",
                    HttpRequestError.SecureConnectionError => "TLS failed",
                    _ => "request failed",
                };
                retry = true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // The type only: messages from the HTTP stack can name the host.
                error = ex.GetType().Name;
                retry = false;
            }

            if (!retry || attempt > Backoff.Length)
            {
                logger.LogWarning("Alert {Type} for {Subject} to {Target} failed after {Attempts} tries: {Error}.",
                    alert.Type, alert.Subject, target.Name, attempt, error);
                return new AlertDelivery(target.Name, false, status, error, attempt);
            }
            await Task.Delay(Backoff[attempt - 1], clock, ct);
        }
    }
}
