namespace SslReverseProxy.Core.Domain;

/// <summary>
/// Proxy traffic over one sample interval: the change in Caddy's counters since
/// the previous sample. Rows older than the dashboard window are pruned.
/// </summary>
public class TrafficSample
{
    public long Id { get; set; }

    /// <summary>End of the interval in Unix seconds; SQLite cannot compare DateTimeOffset in a query.</summary>
    public long At { get; set; }

    public long Requests { get; set; }
    public long Status2xx { get; set; }
    public long Status3xx { get; set; }
    public long Status4xx { get; set; }
    public long Status5xx { get; set; }
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public double DurationSumSeconds { get; set; }
    public double TtfbSumSeconds { get; set; }
    public long TtfbCount { get; set; }

    /// <summary>Response-time histogram, <c>upper:count</c> pairs joined by commas, counts per bucket (not cumulative).</summary>
    public string DurationBuckets { get; set; } = string.Empty;

    /// <summary>Requests in flight when the sample was taken.</summary>
    public long InFlight { get; set; }
}

/// <summary>The dashboard's view of the last day of samples.</summary>
public sealed record TrafficSummary(
    int Samples,
    DateTimeOffset? From,
    DateTimeOffset? To,
    long Requests,
    long BytesIn,
    long BytesOut,
    long? InFlight,
    double? AvgTtfbMs,
    double? AvgResponseMs,
    double? P50Ms,
    double? P90Ms,
    double? P95Ms,
    long Status2xx,
    long Status3xx,
    long Status4xx,
    long Status5xx,
    IReadOnlyList<(DateTimeOffset Start, long Requests)> Hourly)
{
    public static readonly TimeSpan Window = TimeSpan.FromHours(24);

    /// <summary>
    /// Totals over samples taken in the 24 hours to <paramref name="now"/>, and
    /// requests per clock hour for the 24 hours ending with the current one.
    /// Samples older than the first hour are counted in it, so the hours add up
    /// to the total. In-flight comes from the newest sample when it is younger
    /// than <paramref name="inFlightMaxAge"/>.
    /// </summary>
    public static TrafficSummary Compute(IEnumerable<TrafficSample> samples, DateTimeOffset now, TimeSpan inFlightMaxAge)
    {
        var since = now - Window;
        var inWindow = samples
            .Where(s => s.At > since.ToUnixTimeSeconds() && s.At <= now.ToUnixTimeSeconds())
            .OrderBy(s => s.At).ToList();

        var currentHour = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, 0, 0, now.Offset);
        var firstHour = currentHour.AddHours(-23);
        var hourly = new long[24];
        foreach (var s in inWindow)
        {
            var index = (int)Math.Floor((DateTimeOffset.FromUnixTimeSeconds(s.At - 1) - firstHour).TotalHours);
            hourly[Math.Clamp(index, 0, 23)] += s.Requests;
        }

        var buckets = new Dictionary<double, long>();
        foreach (var s in inWindow)
            foreach (var (upper, count) in Histogram.Parse(s.DurationBuckets))
                buckets[upper] = buckets.GetValueOrDefault(upper) + count;
        var histogram = buckets.Select(b => (b.Key, b.Value)).ToList();

        var requests = inWindow.Sum(s => s.Requests);
        var ttfbCount = inWindow.Sum(s => s.TtfbCount);
        var newest = inWindow.LastOrDefault();

        return new TrafficSummary(
            inWindow.Count,
            inWindow.Count > 0 ? DateTimeOffset.FromUnixTimeSeconds(inWindow[0].At) : null,
            newest is null ? null : DateTimeOffset.FromUnixTimeSeconds(newest.At),
            requests,
            inWindow.Sum(s => s.BytesIn),
            inWindow.Sum(s => s.BytesOut),
            newest is not null && now - DateTimeOffset.FromUnixTimeSeconds(newest.At) <= inFlightMaxAge ? newest.InFlight : null,
            ttfbCount > 0 ? inWindow.Sum(s => s.TtfbSumSeconds) / ttfbCount * 1000 : null,
            requests > 0 ? inWindow.Sum(s => s.DurationSumSeconds) / requests * 1000 : null,
            Histogram.Quantile(0.50, histogram) * 1000,
            Histogram.Quantile(0.90, histogram) * 1000,
            Histogram.Quantile(0.95, histogram) * 1000,
            inWindow.Sum(s => s.Status2xx),
            inWindow.Sum(s => s.Status3xx),
            inWindow.Sum(s => s.Status4xx),
            inWindow.Sum(s => s.Status5xx),
            hourly.Select((n, i) => (firstHour.AddHours(i), n)).ToList());
    }
}

public static class Histogram
{
    /// <summary>
    /// Prometheus-style quantile: finds the bucket holding the rank and
    /// interpolates linearly inside it. A rank in the +Inf bucket answers the
    /// highest finite bound. Null when the histogram is empty.
    /// </summary>
    public static double? Quantile(double q, IReadOnlyList<(double Upper, long Count)> buckets)
    {
        var ordered = buckets.OrderBy(b => b.Upper).ToList();
        var total = ordered.Sum(b => b.Count);
        if (total == 0) return null;

        var rank = Math.Clamp(q, 0, 1) * total;
        long below = 0;
        for (var i = 0; i < ordered.Count; i++)
        {
            var (upper, count) = ordered[i];
            if (count > 0 && below + count >= rank)
            {
                var lower = i == 0 ? 0 : ordered[i - 1].Upper;
                if (double.IsPositiveInfinity(upper)) return lower;
                return lower + (upper - lower) * ((rank - below) / count);
            }
            below += count;
        }
        return null;
    }

    public static string Format(IEnumerable<(double Upper, long Count)> buckets) =>
        string.Join(',', buckets.Select(b =>
            $"{(double.IsPositiveInfinity(b.Upper) ? "+Inf" : b.Upper.ToString("R", System.Globalization.CultureInfo.InvariantCulture))}:{b.Count}"));

    public static List<(double Upper, long Count)> Parse(string text)
    {
        var result = new List<(double, long)>();
        foreach (var pair in text.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = pair.LastIndexOf(':');
            if (colon <= 0) continue;
            var upperText = pair[..colon];
            var upper = upperText == "+Inf" ? double.PositiveInfinity
                : double.Parse(upperText, System.Globalization.CultureInfo.InvariantCulture);
            result.Add((upper, long.Parse(pair[(colon + 1)..], System.Globalization.CultureInfo.InvariantCulture)));
        }
        return result;
    }
}
