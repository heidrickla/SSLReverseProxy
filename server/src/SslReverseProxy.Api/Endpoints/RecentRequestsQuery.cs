namespace SslReverseProxy.Api.Endpoints;

/// <summary>Paging and the status filter for a rule's recent requests.</summary>
public static class RecentRequestsQuery
{
    public const int Take = 50;
    public const int MaxTake = 500;

    /// <summary>Null or empty matches all; <c>4xx</c> a class; <c>404</c> one code.</summary>
    public static bool TryStatus(string? value, out Func<int, bool> matches)
    {
        matches = _ => true;
        if (string.IsNullOrEmpty(value)) return true;
        if (value.Length != 3 || value[0] is < '1' or > '5') return false;
        if (value[1..].Equals("xx", StringComparison.OrdinalIgnoreCase))
        {
            var cls = value[0] - '0';
            matches = s => s / 100 == cls;
            return true;
        }
        if (!char.IsAsciiDigit(value[1]) || !char.IsAsciiDigit(value[2])) return false;
        var code = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
        matches = s => s == code;
        return true;
    }
}
