using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace SslReverseProxy.Tests;

/// <summary>Holds one database step of a request until Release: the Nth command whose SQL matches, or the first
/// transaction started after a read of a user by id.</summary>
internal sealed class StepGate : IDbCommandInterceptor, IDbTransactionInterceptor
{
    private readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Func<string, bool> _match = _ => false;
    private int _left = -1;
    private int _transactionArmed;
    private int _userReadSeen;

    public Task Reached => _reached.Task;

    /// <summary>Holds through cancellation, as work that does not watch its token would.</summary>
    public bool IgnoresCancellation { get; init; }

    public static bool UserReadById(string sql) =>
        sql.Contains("FROM \"Users\" AS \"u\"") && sql.Contains("WHERE \"u\".\"Id\" =");

    public void HoldCommand(Func<string, bool> match, int nth = 1)
    {
        _match = match;
        Volatile.Write(ref _left, nth);
    }

    public void HoldUserRead(int nth) => HoldCommand(UserReadById, nth);
    public void HoldTransactionAfterUserRead() => Volatile.Write(ref _transactionArmed, 1);
    public void Release() => _release.TrySetResult();

    public async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
    {
        await Step(command.CommandText, cancellationToken);
        return result;
    }

    public async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        await Step(command.CommandText, cancellationToken);
        return result;
    }

    public async ValueTask<InterceptionResult<DbTransaction>> TransactionStartingAsync(DbConnection connection,
        TransactionStartingEventData eventData, InterceptionResult<DbTransaction> result,
        CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _userReadSeen) == 1 && Interlocked.Exchange(ref _transactionArmed, 0) == 1) await Hold(cancellationToken);
        return result;
    }

    private async Task Step(string sql, CancellationToken ct)
    {
        if (UserReadById(sql) && Volatile.Read(ref _transactionArmed) == 1) Volatile.Write(ref _userReadSeen, 1);
        if (_match(sql) && Interlocked.Decrement(ref _left) == 0) await Hold(ct);
    }

    // The hold ends at Release, after 30 s, or when the request's work is cancelled unless it ignores cancellation.
    private async Task Hold(CancellationToken ct)
    {
        _reached.TrySetResult();
        await _release.Task.WaitAsync(TimeSpan.FromSeconds(30), IgnoresCancellation ? CancellationToken.None : ct);
    }
}
