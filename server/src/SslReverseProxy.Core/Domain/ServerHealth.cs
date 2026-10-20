namespace SslReverseProxy.Core.Domain;

public enum ServerHealthStatus
{
    Unknown = 0,  // not probed yet, or the monitor is off
    Active = 1,   // every upstream of every enabled rule answered
    Inactive = 2, // no enabled rule routes to the server
    Error = 3,    // at least one upstream did not answer
}

/// <summary>A server's status from the last background probe of its enabled rules' upstreams.</summary>
public sealed record ServerHealth(ServerHealthStatus Status, int UpstreamsUp, int UpstreamsTotal, DateTimeOffset? CheckedAt)
{
    public static readonly ServerHealth Unknown = new(ServerHealthStatus.Unknown, 0, 0, null);

    public static ServerHealthStatus Classify(int upstreamsUp, int upstreamsTotal) =>
        upstreamsTotal == 0 ? ServerHealthStatus.Inactive
        : upstreamsUp == upstreamsTotal ? ServerHealthStatus.Active
        : ServerHealthStatus.Error;
}
