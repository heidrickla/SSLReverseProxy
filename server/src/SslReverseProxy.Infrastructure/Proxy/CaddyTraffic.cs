using System.Globalization;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// Caddy's HTTP counters at one scrape, summed over servers, handlers and methods.
/// Caddy labels each request with the first handler of the route it matched, so
/// the sums count every request once. Requests no route matched are not counted.
/// <para>
/// <see cref="LoadedAt"/> is Caddy's last successful reload time. A load with a
/// changed config resets the counters and moves it; an unchanged one does neither.
/// </para>
/// </summary>
public sealed record CaddyTraffic(
    long Requests,
    long Status2xx, long Status3xx, long Status4xx, long Status5xx,
    double BytesIn, double BytesOut,
    double DurationSumSeconds,
    double TtfbSumSeconds, long TtfbCount,
    IReadOnlyDictionary<double, long> DurationCumulative,
    long InFlight,
    double? LoadedAt = null)
{

    public static CaddyTraffic FromMetrics(string prometheusText)
    {
        long requests = 0, s2 = 0, s3 = 0, s4 = 0, s5 = 0, ttfbCount = 0;
        double bytesIn = 0, bytesOut = 0, durationSum = 0, ttfbSum = 0, inFlight = 0;
        double? loadedAt = null;
        var buckets = new Dictionary<double, long>();

        foreach (var (name, labels, value) in PrometheusText.Parse(prometheusText))
        {
            switch (name)
            {
                case "caddy_http_request_duration_seconds_count":
                    var n = (long)value;
                    requests += n;
                    switch (labels.GetValueOrDefault("code") is { Length: 3 } code ? code[0] : ' ')
                    {
                        case '2': s2 += n; break;
                        case '3': s3 += n; break;
                        case '4': s4 += n; break;
                        case '5': s5 += n; break;
                    }
                    break;
                case "caddy_http_request_duration_seconds_sum": durationSum += value; break;
                case "caddy_http_request_duration_seconds_bucket":
                    if (labels.GetValueOrDefault("le") is { } le && ParseBound(le) is { } bound)
                        buckets[bound] = buckets.GetValueOrDefault(bound) + (long)value;
                    break;
                case "caddy_http_response_duration_seconds_sum": ttfbSum += value; break;
                case "caddy_http_response_duration_seconds_count": ttfbCount += (long)value; break;
                case "caddy_http_request_size_bytes_sum": bytesIn += value; break;
                case "caddy_http_response_size_bytes_sum": bytesOut += value; break;
                case "caddy_http_requests_in_flight": inFlight += value; break;
                case "caddy_config_last_reload_success_timestamp_seconds": loadedAt = value; break;
            }
        }

        return new CaddyTraffic(requests, s2, s3, s4, s5, bytesIn, bytesOut, durationSum, ttfbSum, ttfbCount,
            buckets, (long)inFlight, loadedAt);
    }

    /// <summary>
    /// Traffic since <paramref name="earlier"/>. When the counters restarted in
    /// between, the whole current value is new. A different load time says so;
    /// without one, a count lower than before does.
    /// </summary>
    public CaddyTraffic Since(CaddyTraffic earlier)
    {
        var restarted = LoadedAt is { } now && earlier.LoadedAt is { } then
            ? now != then
            : Requests < earlier.Requests || TtfbCount < earlier.TtfbCount
              || DurationCumulative.Any(b => b.Value < earlier.DurationCumulative.GetValueOrDefault(b.Key));
        if (restarted) return this;

        var buckets = DurationCumulative.ToDictionary(
            b => b.Key, b => b.Value - earlier.DurationCumulative.GetValueOrDefault(b.Key));
        return new CaddyTraffic(
            Requests - earlier.Requests,
            Status2xx - earlier.Status2xx, Status3xx - earlier.Status3xx,
            Status4xx - earlier.Status4xx, Status5xx - earlier.Status5xx,
            BytesIn - earlier.BytesIn, BytesOut - earlier.BytesOut,
            DurationSumSeconds - earlier.DurationSumSeconds,
            TtfbSumSeconds - earlier.TtfbSumSeconds, TtfbCount - earlier.TtfbCount,
            buckets, InFlight, LoadedAt);
    }

    public CaddyTraffic Plus(CaddyTraffic other)
    {
        var buckets = DurationCumulative.Keys.Union(other.DurationCumulative.Keys).ToDictionary(
            k => k, k => DurationCumulative.GetValueOrDefault(k) + other.DurationCumulative.GetValueOrDefault(k));
        return new CaddyTraffic(
            Requests + other.Requests,
            Status2xx + other.Status2xx, Status3xx + other.Status3xx,
            Status4xx + other.Status4xx, Status5xx + other.Status5xx,
            BytesIn + other.BytesIn, BytesOut + other.BytesOut,
            DurationSumSeconds + other.DurationSumSeconds,
            TtfbSumSeconds + other.TtfbSumSeconds, TtfbCount + other.TtfbCount,
            buckets, other.InFlight, other.LoadedAt);
    }

    /// <summary>Per-bucket counts from the cumulative ones, for storage.</summary>
    public IEnumerable<(double Upper, long Count)> DurationBuckets()
    {
        long below = 0;
        foreach (var (upper, cumulative) in DurationCumulative.OrderBy(b => b.Key))
        {
            yield return (upper, Math.Max(0, cumulative - below));
            below = cumulative;
        }
    }

    public TrafficSample ToSample(DateTimeOffset at) => new()
    {
        At = at.ToUnixTimeSeconds(),
        Requests = Requests,
        Status2xx = Status2xx,
        Status3xx = Status3xx,
        Status4xx = Status4xx,
        Status5xx = Status5xx,
        BytesIn = (long)BytesIn,
        BytesOut = (long)BytesOut,
        DurationSumSeconds = DurationSumSeconds,
        TtfbSumSeconds = TtfbSumSeconds,
        TtfbCount = TtfbCount,
        DurationBuckets = Histogram.Format(DurationBuckets()),
        InFlight = InFlight,
    };

    private static double? ParseBound(string le) =>
        le == "+Inf" ? double.PositiveInfinity
        : double.TryParse(le, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : null;
}

/// <summary>Prometheus text exposition: one (name, labels, value) per sample line.</summary>
public static class PrometheusText
{
    public static IEnumerable<(string Name, IReadOnlyDictionary<string, string> Labels, double Value)> Parse(string text)
    {
        if (string.IsNullOrEmpty(text)) yield break;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            if (TryParseLine(line, out var name, out var labels, out var value))
                yield return (name, labels, value);
        }
    }

    private static bool TryParseLine(string line, out string name, out IReadOnlyDictionary<string, string> labels, out double value)
    {
        var parsed = new Dictionary<string, string>(StringComparer.Ordinal);
        labels = parsed;
        value = 0;

        var i = 0;
        while (i < line.Length && line[i] != '{' && line[i] != ' ') i++;
        name = line[..i];
        if (name.Length == 0) return false;

        if (i < line.Length && line[i] == '{')
        {
            i++;
            while (i < line.Length && line[i] != '}')
            {
                if (line[i] is ',' or ' ') { i++; continue; }
                var eq = line.IndexOf('=', i);
                if (eq < 0 || eq + 1 >= line.Length || line[eq + 1] != '"') return false;
                var key = line[i..eq];
                var sb = new System.Text.StringBuilder();
                var j = eq + 2;
                for (; j < line.Length && line[j] != '"'; j++)
                {
                    if (line[j] == '\\' && j + 1 < line.Length)
                    {
                        j++;
                        sb.Append(line[j] == 'n' ? '\n' : line[j]);
                    }
                    else sb.Append(line[j]);
                }
                if (j >= line.Length) return false;
                parsed[key] = sb.ToString();
                i = j + 1;
            }
            if (i >= line.Length) return false;
            i++;
        }

        var rest = line[i..].Trim();
        var space = rest.IndexOf(' ');
        var token = space < 0 ? rest : rest[..space];
        return double.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, out value)
            || ParseSpecial(token, out value);
    }

    private static bool ParseSpecial(string token, out double value)
    {
        value = token switch { "+Inf" => double.PositiveInfinity, "-Inf" => double.NegativeInfinity, "NaN" => double.NaN, _ => 0 };
        return token is "+Inf" or "-Inf" or "NaN";
    }
}
