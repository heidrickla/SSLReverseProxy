using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using SslReverseProxy.Api.Auth;

namespace SslReverseProxy.Api.Contracts;

/// <summary>Names the API and declares the API key every operation takes.</summary>
public static class OpenApiDescription
{
    public static Task Describe(Microsoft.OpenApi.OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken ct)
    {
        document.Info.Title = "SSLReverseProxy API";
        document.Info.Version = $"v{ApiContract.ApiVersion}";
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes[ApiKeyDefaults.Scheme] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.ApiKey,
            In = ParameterLocation.Header,
            Name = ApiKeyDefaults.HeaderName,
            Description = "An API key, srp.<prefix>.<secret>. Authorization: Bearer <key> is also accepted.",
        };
        document.Security ??= [];
        document.Security.Add(new OpenApiSecurityRequirement
        {
            [new OpenApiSecuritySchemeReference(ApiKeyDefaults.Scheme, document)] = [],
        });
        return Task.CompletedTask;
    }
}
