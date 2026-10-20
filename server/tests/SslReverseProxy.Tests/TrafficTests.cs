using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Proxy;
using Xunit;

namespace SslReverseProxy.Tests;

public class PrometheusTextTests
{
    [Fact]
    public void Parses_EscapedLabelValues()
    {
        var (name, labels, value) = PrometheusText.Parse(
            "m{a=\"q\\\"uote\",b=\"back\\\\slash\",c=\"new\\nline\"} 2.5").Single();
        Assert.Equal("m", name);
        Assert.Equal("q\"uote", labels["a"]);
        Assert.Equal("back\\slash", labels["b"]);
        Assert.Equal("new\nline", labels["c"]);
        Assert.Equal(2.5, value);
    }

    [Fact]
    public void Parses_SpecialValues_AndSkipsCommentsAndMalformedLines()
    {
        var parsed = PrometheusText.Parse("""
            # HELP m A metric.
            # TYPE m gauge
            m{le="+Inf"} +Inf
            n NaN
            o 1e+09 1700000000000
            broken{a="unterminated} 1
            novalue{a="b"}
            """).ToList();

        Assert.Equal(["m", "n", "o"], parsed.Select(p => p.Name));
        Assert.True(double.IsPositiveInfinity(parsed[0].Value));
        Assert.True(double.IsNaN(parsed[1].Value));
        Assert.Equal(1e9, parsed[2].Value); // the timestamp is not the value
    }
}

public class CaddyTrafficTests
{
    // Lines as Caddy 2.11.7 wrote them: one label set per code and first handler.
    internal const string Scrape = """
        # HELP caddy_config_last_reload_success_timestamp_seconds Timestamp of the last successful configuration reload.
        caddy_config_last_reload_success_timestamp_seconds 1.792516980454113e+09
        caddy_http_request_duration_seconds_bucket{code="200",handler="headers",method="GET",server="https",le="0.005"} 1
        caddy_http_request_duration_seconds_bucket{code="200",handler="headers",method="GET",server="https",le="0.25"} 1
        caddy_http_request_duration_seconds_bucket{code="200",handler="headers",method="GET",server="https",le="+Inf"} 1
        caddy_http_request_duration_seconds_sum{code="200",handler="headers",method="GET",server="https"} 0.0010042
        caddy_http_request_duration_seconds_count{code="200",handler="headers",method="GET",server="https"} 1
        caddy_http_request_duration_seconds_bucket{code="308",handler="static_response",method="GET",server="http",le="0.005"} 2
        caddy_http_request_duration_seconds_bucket{code="308",handler="static_response",method="GET",server="http",le="0.25"} 2
        caddy_http_request_duration_seconds_bucket{code="308",handler="static_response",method="GET",server="http",le="+Inf"} 2
        caddy_http_request_duration_seconds_sum{code="308",handler="static_response",method="GET",server="http"} 0
        caddy_http_request_duration_seconds_count{code="308",handler="static_response",method="GET",server="http"} 2
        caddy_http_request_duration_seconds_bucket{code="401",handler="headers",method="GET",server="https",le="0.005"} 0
        caddy_http_request_duration_seconds_bucket{code="401",handler="headers",method="GET",server="https",le="0.25"} 2
        caddy_http_request_duration_seconds_bucket{code="401",handler="headers",method="GET",server="https",le="+Inf"} 2
        caddy_http_request_duration_seconds_sum{code="401",handler="headers",method="GET",server="https"} 0.0053382
        caddy_http_request_duration_seconds_count{code="401",handler="headers",method="GET",server="https"} 2
        caddy_http_request_size_bytes_sum{code="200",handler="headers",method="GET",server="https"} 70
        caddy_http_request_size_bytes_sum{code="308",handler="static_response",method="GET",server="http"} 122
        caddy_http_request_size_bytes_sum{code="401",handler="headers",method="GET",server="https"} 128
        caddy_http_requests_in_flight{handler="headers",server="https"} 1
        caddy_http_requests_in_flight{handler="static_response",server="http"} 0
        caddy_http_response_duration_seconds_sum{code="200",handler="headers",method="GET",server="https"} 0.0010042
        caddy_http_response_duration_seconds_count{code="200",handler="headers",method="GET",server="https"} 1
        caddy_http_response_duration_seconds_sum{code="308",handler="static_response",method="GET",server="http"} 0
        caddy_http_response_duration_seconds_count{code="308",handler="static_response",method="GET",server="http"} 2
        caddy_http_response_duration_seconds_sum{code="401",handler="headers",method="GET",server="https"} 0.0053382
        caddy_http_response_duration_seconds_count{code="401",handler="headers",method="GET",server="https"} 2
        caddy_http_response_size_bytes_sum{code="200",handler="headers",method="GET",server="https"} 15
        caddy_http_response_size_bytes_sum{code="308",handler="static_response",method="GET",server="http"} 0
        caddy_http_response_size_bytes_sum{code="401",handler="headers",method="GET",server="https"} 330
        """;

    internal static CaddyTraffic Traffic(long requests, double? loadedAt = 1000, long inFlight = 0) =>
        new(requests, requests, 0, 0, 0, requests * 10, requests * 20, requests * 0.01, requests * 0.005, requests,
            new Dictionary<double, long> { [0.25] = requests, [double.PositiveInfinity] = requests }, inFlight, loadedAt);

    [Fact]
    public void FromMetrics_SumsAcrossServersHandlersAndCodes()
    {
        var t = CaddyTraffic.FromMetrics(Scrape);
        Assert.Equal(5, t.Requests);
        Assert.Equal((1, 2, 2, 0), (t.Status2xx, t.Status3xx, t.Status4xx, t.Status5xx));
        Assert.Equal(320, t.BytesIn);
        Assert.Equal(345, t.BytesOut);
        Assert.Equal(0.0063424, t.DurationSumSeconds, 9);
        Assert.Equal(5, t.TtfbCount);
        Assert.Equal(0.0063424, t.TtfbSumSeconds, 9);
        Assert.Equal(1, t.InFlight);
        Assert.Equal(1.792516980454113e+09, t.LoadedAt);
        Assert.Equal(3, t.DurationCumulative[0.005]);
        Assert.Equal(5, t.DurationCumulative[0.25]);
        Assert.Equal(5, t.DurationCumulative[double.PositiveInfinity]);
    }

    [Fact]
    public void DurationBuckets_ArePerBucket_NotCumulative()
    {
        var buckets = CaddyTraffic.FromMetrics(Scrape).DurationBuckets().ToList();
        Assert.Equal([(0.005, 3L), (0.25, 2L), (double.PositiveInfinity, 0L)], buckets);
    }

    [Fact]
    public void Since_SubtractsWithinOneLoad()
    {
        var d = Traffic(7).Since(Traffic(3));
        Assert.Equal(4, d.Requests);
        Assert.Equal(40, d.BytesIn);
        Assert.Equal(4, d.DurationCumulative[0.25]);
    }

    [Fact]
    public void Since_TakesEverything_AfterAReload_EvenWhenTheCountGrewPastTheOldOne()
    {
        // The counters restarted at the reload; 7 requests since then, not 7 - 3.
        var d = Traffic(7, loadedAt: 2000).Since(Traffic(3, loadedAt: 1000));
        Assert.Equal(7, d.Requests);
    }

    [Fact]
    public void Since_FallsBackToACountDrop_WithoutALoadTime()
    {
        Assert.Equal(2, Traffic(2, loadedAt: null).Since(Traffic(5, loadedAt: null)).Requests);
        Assert.Equal(3, Traffic(8, loadedAt: null).Since(Traffic(5, loadedAt: null)).Requests);
    }

    [Fact]
    public void ToSample_StoresPerBucketCounts()
    {
        var at = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var s = CaddyTraffic.FromMetrics(Scrape).ToSample(at);
        Assert.Equal(1_800_000_000, s.At);
        Assert.Equal(5, s.Requests);
        Assert.Equal("0.005:3,0.25:2,+Inf:0", s.DurationBuckets);
    }
}

public class TrafficRecorderTests
{
    [Fact]
    public void CountsEachRequestOnce_AcrossScrapesReloadsAndRestarts()
    {
        var r = new TrafficRecorder();
        Assert.Null(r.TakePending());

        r.Observe(CaddyTrafficTests.Traffic(3));             // first scrape: all new
        r.Observe(CaddyTrafficTests.Traffic(5));             // +2
        Assert.Equal(5, r.TakePending()!.Requests);
        Assert.Null(r.TakePending());

        r.Observe(CaddyTrafficTests.Traffic(9, loadedAt: 2000));  // reload, then 9
        r.Observe(CaddyTrafficTests.Traffic(10, loadedAt: 2000)); // +1
        Assert.Equal(10, r.TakePending()!.Requests);

        r.ProcessStopped();
        r.Observe(CaddyTrafficTests.Traffic(4, loadedAt: 2000)); // new process, same load time is not trusted
        Assert.Equal(4, r.TakePending()!.Requests);
    }

    [Fact]
    public void InFlight_IsTheLatestReading_NotASum()
    {
        var r = new TrafficRecorder();
        r.Observe(CaddyTrafficTests.Traffic(1, inFlight: 4));
        r.Observe(CaddyTrafficTests.Traffic(2, inFlight: 1));
        Assert.Equal(1, r.TakePending()!.InFlight);
    }
}

public class HistogramTests
{
    [Theory]
    [InlineData(0.5, 0.1)]   // rank 5 closes the first bucket
    [InlineData(0.75, 0.15)] // halfway through the second
    [InlineData(1.0, 0.2)]
    public void Quantile_InterpolatesInsideTheBucket(double q, double expected)
    {
        var q2 = Histogram.Quantile(q, [(0.1, 5), (0.2, 5)]);
        Assert.Equal(expected, q2!.Value, 9);
    }

    [Fact]
    public void Quantile_InTheInfBucket_IsTheHighestFiniteBound()
    {
        Assert.Equal(0.5, Histogram.Quantile(0.99, [(0.5, 1), (double.PositiveInfinity, 9)]));
    }

    [Fact]
    public void Quantile_IsNull_ForAnEmptyHistogram()
    {
        Assert.Null(Histogram.Quantile(0.5, []));
        Assert.Null(Histogram.Quantile(0.5, [(0.1, 0), (double.PositiveInfinity, 0)]));
    }

    [Fact]
    public void FormatAndParse_RoundTrip()
    {
        List<(double, long)> buckets = [(0.005, 3), (0.25, 2), (double.PositiveInfinity, 1)];
        Assert.Equal(buckets, Histogram.Parse(Histogram.Format(buckets)));
        Assert.Empty(Histogram.Parse(""));
    }
}

public class TrafficSummaryTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 12, 30, 0, TimeSpan.Zero);

    private static TrafficSample Sample(DateTimeOffset at, long requests, long inFlight = 0) => new()
    {
        At = at.ToUnixTimeSeconds(),
        Requests = requests,
        Status2xx = requests,
        BytesIn = requests * 100,
        BytesOut = requests * 1000,
        DurationSumSeconds = requests * 0.02,
        TtfbSumSeconds = requests * 0.01,
        TtfbCount = requests,
        DurationBuckets = Histogram.Format([(0.01, 0), (0.025, requests), (double.PositiveInfinity, 0)]),
        InFlight = inFlight,
    };

    [Fact]
    public void Compute_TotalsTheDay_AndBucketsItByHour()
    {
        var samples = new[]
        {
            Sample(Now.AddHours(-25), 1000),                      // outside the day
            Sample(Now.AddMinutes(1), 1000),                      // in the future
            Sample(Now.AddHours(-23).AddMinutes(-45), 1),         // before the first hour: counted in it
            Sample(new DateTimeOffset(2026, 10, 20, 12, 0, 0, TimeSpan.Zero), 2), // ends 11:00-12:00
            Sample(Now.AddMinutes(-10), 3, inFlight: 4),
        };

        var t = TrafficSummary.Compute(samples, Now, TimeSpan.FromMinutes(15));

        Assert.Equal(3, t.Samples);
        Assert.Equal(6, t.Requests);
        Assert.Equal(600, t.BytesIn);
        Assert.Equal(6000, t.BytesOut);
        Assert.Equal(6, t.Status2xx);
        Assert.Equal(20, t.AvgResponseMs!.Value, 9);
        Assert.Equal(10, t.AvgTtfbMs!.Value, 9);
        Assert.Equal(17.5, t.P50Ms!.Value, 9);
        Assert.Equal(4, t.InFlight);

        Assert.Equal(24, t.Hourly.Count);
        Assert.Equal(new DateTimeOffset(2026, 10, 19, 13, 0, 0, TimeSpan.Zero), t.Hourly[0].Start);
        Assert.Equal(1, t.Hourly[0].Requests);
        Assert.Equal(2, t.Hourly[22].Requests);
        Assert.Equal(3, t.Hourly[23].Requests);
        Assert.Equal(t.Requests, t.Hourly.Sum(h => h.Requests));
    }

    [Fact]
    public void Compute_DropsInFlight_FromAStaleSample()
    {
        var t = TrafficSummary.Compute([Sample(Now.AddMinutes(-20), 1, inFlight: 4)], Now, TimeSpan.FromMinutes(15));
        Assert.Null(t.InFlight);
        Assert.Equal(1, t.Requests);
    }

    [Fact]
    public void Compute_WithNoSamples_HasNoAveragesOrQuantiles()
    {
        var t = TrafficSummary.Compute([], Now, TimeSpan.FromMinutes(15));
        Assert.Equal(0, t.Samples);
        Assert.Null(t.From);
        Assert.Null(t.AvgResponseMs);
        Assert.Null(t.AvgTtfbMs);
        Assert.Null(t.P95Ms);
        Assert.Null(t.InFlight);
        Assert.Equal(24, t.Hourly.Count);
    }
}
