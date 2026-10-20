# Bundles the control-plane API with the Caddy binary in one image. The API owns
# the Caddy child process (start/stop) and talks to it over the loopback admin
# API — matching CaddyProxyController's model.

# Caddy, the caddy-ratelimit plugin that per-rule rate limits need, and the
# Cloudflare DNS provider for DNS-01 challenges. CI reads these pins from here,
# so tests and the image run the same build.
ARG CADDY_VERSION=2.11.7
ARG CADDY_RATELIMIT=5625512f24f6f59d6f64fb3aafe5eecff0b286db
ARG CADDY_CLOUDFLARE=v0.2.4

FROM caddy:${CADDY_VERSION}-builder AS caddy
ARG CADDY_VERSION
ARG CADDY_RATELIMIT
ARG CADDY_CLOUDFLARE
RUN xcaddy build v${CADDY_VERSION} \
    --with github.com/mholt/caddy-ratelimit@${CADDY_RATELIMIT} \
    --with github.com/caddy-dns/cloudflare@${CADDY_CLOUDFLARE} \
    --output /usr/bin/caddy

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore src/SslReverseProxy.Api/SslReverseProxy.Api.csproj
RUN dotnet publish src/SslReverseProxy.Api/SslReverseProxy.Api.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

# For the compose healthcheck; the .NET runtime images ship without it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=caddy /usr/bin/caddy /usr/bin/caddy

COPY --from=build /app .

# Persisted data (SQLite DB + generated proxy config + Caddy's cert store).
VOLUME /data
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_URLS=http://+:8080 \
    ConnectionStrings__AppDb="Data Source=/data/sslrp.db" \
    Proxy__ConfigDirectory=/data/proxy-config \
    XDG_DATA_HOME=/data

# 8080 = control API; 80/443 = the proxy (Caddy, started by the API).
EXPOSE 8080 80 443

ENTRYPOINT ["dotnet", "SslReverseProxy.Api.dll"]
