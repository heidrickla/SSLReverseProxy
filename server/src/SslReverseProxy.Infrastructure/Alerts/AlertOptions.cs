namespace SslReverseProxy.Infrastructure.Alerts;

public sealed class AlertOptions
{
    public const string SectionName = "Alerts";

    public List<AlertTargetOptions> Targets { get; set; } = [];

    /// <summary>Consecutive Error readings before a server alerts as down.</summary>
    public int ServerDownChecks { get; set; } = 2;
}

public sealed class AlertTargetOptions
{
    public string? Name { get; set; }

    /// <summary><c>webhook</c> (a JSON POST, as Home Assistant's webhook trigger takes) or <c>ntfy</c>.</summary>
    public string? Kind { get; set; }

    /// <summary>A secret: a Home Assistant webhook id or an ntfy topic grants access by itself.</summary>
    public string? Url { get; set; }

    /// <summary>Sent as <c>Authorization: Bearer</c> when set.</summary>
    public string? Token { get; set; }

    /// <summary>Alert types to send; empty sends every type.</summary>
    public List<string> Events { get; set; } = [];
}
