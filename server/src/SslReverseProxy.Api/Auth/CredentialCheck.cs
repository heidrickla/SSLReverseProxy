using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Persistence;

namespace SslReverseProxy.Api.Auth;

/// <summary>
/// Rereads the credential a long-lived request signed in with, for checks after authentication has run.
/// </summary>
public static class CredentialCheck
{
    /// <summary>
    /// When the key or session behind <paramref name="user"/> stops being valid, or null when it is not valid
    /// now: revoked, expired, its owner inactive, a session's role changed, or <paramref name="needed"/> no
    /// longer held. A key that does not expire is valid until <see cref="DateTimeOffset.MaxValue"/>.
    /// </summary>
    public static async Task<DateTimeOffset?> ValidUntilAsync(
        ClaimsPrincipal user, Permission needed, AppDbContext db, DateTimeOffset now, CancellationToken ct)
    {
        if (Guid.TryParse(user.FindFirstValue(ApiKeyDefaults.KeyClaim), out var keyId))
        {
            var key = await db.ApiKeys.AsNoTracking().Include(k => k.User).FirstOrDefaultAsync(k => k.Id == keyId, ct);
            if (key is null || !key.IsActive(now) || key.User is not { IsActive: true } owner
                || !Permissions.Effective(owner.Role, ApiKeyScopes.Parse(key.Scopes)).Contains(needed))
                return null;
            return key.ExpiresAt ?? DateTimeOffset.MaxValue;
        }

        if (Guid.TryParse(user.FindFirstValue(ApiKeyDefaults.SessionClaim), out var sessionId))
        {
            var session = await db.Sessions.AsNoTracking().Include(s => s.User).FirstOrDefaultAsync(s => s.Id == sessionId, ct);
            if (session is null || session.RevokedAt is not null || session.ExpiresAt <= now
                || session.User is not { IsActive: true } owner || owner.Role != session.Role
                || !Permissions.For(owner.Role).Contains(needed))
                return null;
            return session.ExpiresAt;
        }

        return null;
    }
}
