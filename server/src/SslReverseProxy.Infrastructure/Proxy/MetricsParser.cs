using System.Globalization;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// Minimal Prometheus text-format parser for the handful of Caddy series the
/// dashboard needs. Sums families across their label sets.
/// </summary>
public static class MetricsParser
{
    public static IReadOnlyDictionary<string, double> Parse(string prometheusText)
    {
        var sums = new Dictionary<string, double>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(prometheusText)) return sums;

        foreach (var raw in prometheusText.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;

            // <name>{labels} <value> [timestamp]  OR  <name> <value>
            var braceIdx = line.IndexOf('{');
            string name;
            string rest;
            if (braceIdx >= 0)
            {
                name = line[..braceIdx];
                var closeIdx = line.IndexOf('}', braceIdx);
                if (closeIdx < 0) continue;
                rest = line[(closeIdx + 1)..].Trim();
            }
            else
            {
                var sp = line.IndexOf(' ');
                if (sp < 0) continue;
                name = line[..sp];
                rest = line[(sp + 1)..].Trim();
            }

            var valueToken = rest.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (valueToken is null) continue;
            if (!double.TryParse(valueToken, NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
                continue;

            sums[name] = sums.TryGetValue(name, out var acc) ? acc + value : value;
        }

        return sums;
    }
}
