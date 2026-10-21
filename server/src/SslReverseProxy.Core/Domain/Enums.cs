namespace SslReverseProxy.Core.Domain;

/// <summary>Coarse role assigned to a principal (user or API key).</summary>
public enum Role
{
    Viewer = 0,
    Editor = 1,
    Admin = 2,
}

/// <summary>Fine-grained actions guarded by authorization policies.</summary>
public enum Permission
{
    ProxyControl,   // start, stop and roll back the proxy
    ServerRead,
    ServerWrite,
    RuleWrite,
    CertRead,
    CertWrite,
    UserWrite,
    ApiKeyManage,
    AuditRead,
    AlertManage,    // list alert targets and send test alerts
    ProxyReload,    // preview, validate and reload the config built from the rules
    CertRenew,      // force a certificate renewal
    BackupManage,   // export and import servers, rules and certificate definitions
    RecentRequestsRead, // a rule's recent requests: paths and client addresses
}

/// <summary>Lifecycle state of the managed reverse-proxy process.</summary>
public enum ProxyState
{
    Unknown = 0,
    Stopped = 1,
    Running = 2,
    Faulted = 3,
    Unavailable = 4, // proxy binary not installed / not configured
}

public enum CertificateStatus
{
    Unknown = 0,
    Valid = 1,
    Expiring = 2,
    Expired = 3,
    Issuing = 4,
    Failed = 5,
}

/// <summary>Why a certificate row exists: a TLS rule's host, or a name registered on its own.</summary>
public enum CertificateSource
{
    Rule = 0,
    Manual = 1,
}

/// <summary>How the ACME CA validates the name.</summary>
public enum CertificateChallenge
{
    Http = 0,
    DnsCloudflare = 1,
}
