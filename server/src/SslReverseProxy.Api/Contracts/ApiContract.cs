namespace SslReverseProxy.Api.Contracts;

/// <summary>
/// What clients such as the Home Assistant integration check before they rely on the API. ApiVersion rises
/// when a change breaks an existing client; a capability is added with the feature it names.
/// </summary>
public static class ApiContract
{
    public const int ApiVersion = 1;

    public static readonly IReadOnlyList<string> Capabilities = ["scoped-api-keys", "push-preview", "backup"];
}

public sealed record InstanceDto(Guid InstanceId, int ApiVersion, string[] Capabilities);
