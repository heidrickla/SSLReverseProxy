using System.Threading.Channels;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Alerts;

namespace SslReverseProxy.Api.Alerts;

/// <summary>
/// Queues alerts from the monitors and sends each to the targets subscribed to its type, all targets of
/// one alert at once. A full queue drops the new alert and logs its type.
/// </summary>
public sealed class AlertDispatcher : BackgroundService, IAlertSink
{
    private const int QueueCapacity = 100;

    private readonly AlertSender _sender;
    private readonly ILogger<AlertDispatcher> _logger;
    private readonly Channel<Alert> _queue = Channel.CreateBounded<Alert>(
        new BoundedChannelOptions(QueueCapacity) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });

    public AlertDispatcher(AlertSender sender, IOptions<AlertOptions> options, ILogger<AlertDispatcher> logger)
    {
        _sender = sender;
        _logger = logger;
        Targets = AlertTargets.From(options.Value);
        foreach (var t in Targets.Where(t => !t.Usable))
            _logger.LogWarning("Alert target {Target} is not used: {Problem}", t.Name, t.Problem);
    }

    public IReadOnlyList<AlertTarget> Targets { get; }

    public void Raise(Alert alert)
    {
        if (!Targets.Any(t => t.Wants(alert.Type))) return;
        if (!_queue.Writer.TryWrite(alert))
            _logger.LogWarning("Alert queue is full; {Type} for {Subject} was dropped.", alert.Type, alert.Subject);
    }

    /// <summary>Sends a test alert to the named target, or to every usable target, and waits for the outcome.</summary>
    public Task<AlertDelivery[]> TestAsync(IEnumerable<AlertTarget> targets, string actor, DateTimeOffset now, CancellationToken ct) =>
        Task.WhenAll(targets.Select(t => _sender.SendAsync(t,
            new Alert(AlertTypes.Test, AlertSeverity.Info, t.Name, "SSLReverseProxy test alert",
                $"Test alert to {t.Name}, sent by {actor}.", now), ct)));

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var alert in _queue.Reader.ReadAllAsync(stoppingToken))
                await Task.WhenAll(Targets.Where(t => t.Wants(alert.Type))
                    .Select(t => _sender.SendAsync(t, alert, stoppingToken)));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutting down; queued alerts are not sent.
        }
    }
}
