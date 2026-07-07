# Bundles the control-plane API with the Caddy binary in one image. The API owns
# the Caddy child process (start/stop) and talks to it over the loopback admin
# API — matching CaddyProxyController's model.

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore src/SslReverseProxy.Api/SslReverseProxy.Api.csproj
RUN dotnet publish src/SslReverseProxy.Api/SslReverseProxy.Api.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

# Pull the Caddy binary from its official image.
COPY --from=caddy:2 /usr/bin/caddy /usr/bin/caddy

COPY --from=build /app .

# Persisted data (SQLite DB + generated proxy config + Caddy's cert store).
VOLUME /data
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_URLS=http://+:8080 \
    XDG_DATA_HOME=/data

# 8080 = control API; 80/443 = the proxy (Caddy, started by the API).
EXPOSE 8080 80 443

ENTRYPOINT ["dotnet", "SslReverseProxy.Api.dll"]
