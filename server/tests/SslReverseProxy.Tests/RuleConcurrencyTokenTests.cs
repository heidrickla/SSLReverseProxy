using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using Xunit;

namespace SslReverseProxy.Tests;

/// <summary>
/// The If-Match check narrows the window between reading a rule and writing it,
/// but cannot close it — two requests can both pass the check and then race to
/// save. These cover the layer underneath, where the database is the only thing
/// in a position to notice.
/// </summary>
public class RuleConcurrencyTokenTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly DbContextOptions<AppDbContext> _options;
    private readonly Guid _ruleId;

    public RuleConcurrencyTokenTests()
    {
        // A shared in-memory database, kept alive by holding the connection
        // open, so several contexts see the same rows.
        _conn = new SqliteConnection("Filename=:memory:");
        _conn.Open();
        _options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_conn).Options;

        using var db = new AppDbContext(_options);
        db.Database.EnsureCreated();
        var server = new ProxyServer { Name = "s", Host = "10.0.0.1" };
        var rule = new ProxyRule
        {
            ServerId = server.Id,
            Domain = "a.example.com",
            UpstreamUrl = "http://10.0.0.5",
            AllowedCidrs = "203.0.113.0/24",
        };
        db.Servers.Add(server);
        db.Rules.Add(rule);
        db.SaveChanges();
        _ruleId = rule.Id;
    }

    [Fact]
    public async Task AWriteFromAStaleCopy_IsRejectedRatherThanApplied()
    {
        using var first = new AppDbContext(_options);
        using var second = new AppDbContext(_options);

        // Both operators load the same rule.
        var byFirst = await first.Rules.SingleAsync(r => r.Id == _ruleId);
        var bySecond = await second.Rules.SingleAsync(r => r.Id == _ruleId);

        byFirst.UpstreamUrl = "http://10.0.0.6";
        byFirst.Version++;
        await first.SaveChangesAsync();

        // The second still holds the version it read, so its UPDATE matches no
        // row. Without the token this would overwrite the first write wholesale.
        bySecond.UpstreamUrl = "http://10.0.0.7";
        bySecond.AllowedCidrs = null; // the kind of collateral loss this prevents
        bySecond.Version++;
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());

        using var check = new AppDbContext(_options);
        var current = await check.Rules.SingleAsync(r => r.Id == _ruleId);
        Assert.Equal("http://10.0.0.6", current.UpstreamUrl);
        Assert.Equal("203.0.113.0/24", current.AllowedCidrs);
    }

    [Fact]
    public async Task SequentialWritesEachAdvanceTheVersion()
    {
        for (var expected = 1; expected <= 3; expected++)
        {
            using var db = new AppDbContext(_options);
            var rule = await db.Rules.SingleAsync(r => r.Id == _ruleId);
            rule.Version++;
            await db.SaveChangesAsync();
            Assert.Equal(expected, rule.Version);
        }
    }

    [Fact]
    public async Task ReloadingAfterAConflict_LetsTheWriteThrough()
    {
        // The recovery an operator is told to perform: reload, reapply, retry.
        using var stale = new AppDbContext(_options);
        var byStale = await stale.Rules.SingleAsync(r => r.Id == _ruleId);

        using (var other = new AppDbContext(_options))
        {
            var theirs = await other.Rules.SingleAsync(r => r.Id == _ruleId);
            theirs.Domain = "moved.example.com";
            theirs.Version++;
            await other.SaveChangesAsync();
        }

        byStale.UpstreamUrl = "http://10.0.0.9";
        byStale.Version++;
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => stale.SaveChangesAsync());

        using var retry = new AppDbContext(_options);
        var fresh = await retry.Rules.SingleAsync(r => r.Id == _ruleId);
        fresh.UpstreamUrl = "http://10.0.0.9";
        fresh.Version++;
        await retry.SaveChangesAsync();

        using var check = new AppDbContext(_options);
        var current = await check.Rules.SingleAsync(r => r.Id == _ruleId);
        Assert.Equal("http://10.0.0.9", current.UpstreamUrl);
        Assert.Equal("moved.example.com", current.Domain); // the other write survived
    }

    public void Dispose() => _conn.Dispose();
}
