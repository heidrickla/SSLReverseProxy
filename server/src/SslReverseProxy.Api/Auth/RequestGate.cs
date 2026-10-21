using System.Collections.Concurrent;
using System.Data.Common;
using System.Runtime.ExceptionServices;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SslReverseProxy.Api.Security;

namespace SslReverseProxy.Api.Auth;

/// <summary>
/// Runs state-changing requests one at a time, from before authentication through the effect and its audit row, so
/// a change to who may do what lands wholly before or wholly after each of them. Reads and the event stream stay
/// outside. The process is the only writer of its database, so one in-process gate covers every request. A turn holds
/// only server work: the request body is read before it and the response sent after it. It ends at
/// <see cref="SecurityOptions.StateChangeSeconds"/> whether or not the work stops; the gate passes on once any
/// database write under way finishes, and the request can write or commit nothing after that.
/// </summary>
public sealed class RequestGate
{
    /// <summary>The most a state-changing request may send when its endpoint declares no limit.</summary>
    public const long DefaultBodyLimit = 1024 * 1024;

    private readonly SemaphoreSlim _gate = new(1, 1);

    public Task WaitAsync(CancellationToken ct) => _gate.WaitAsync(ct);

    public void Release() => _gate.Release();

    /// <summary>Every method but GET, HEAD and OPTIONS, and any endpoint marked with <see cref="ChangesState"/>.</summary>
    public static bool Covers(HttpContext ctx) =>
        !(HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsHead(ctx.Request.Method)
            || HttpMethods.IsOptions(ctx.Request.Method))
        || ctx.GetEndpoint()?.Metadata.GetMetadata<ChangesState>() is not null;

    public static bool Holds(HttpContext ctx) => ctx.Features.Get<Turn>() is { Ended: false };

    /// <summary>The endpoint's declared request size limit, or <see cref="DefaultBodyLimit"/> when it sets none.</summary>
    public static long BodyLimit(HttpContext ctx) =>
        ctx.GetEndpoint()?.Metadata.GetMetadata<IRequestSizeLimitMetadata>()?.MaxRequestBodySize ?? DefaultBodyLimit;

    /// <summary>
    /// One request's hold on the gate. It ends when the request finishes or at the deadline, whichever is first, and
    /// the gate is released once it has ended and no database change it began is still running.
    /// </summary>
    public sealed class Turn(RequestGate gate)
    {
        private readonly Lock _lock = new();
        private int _running;
        private bool _ended;
        private bool _released;

        public bool Ended
        {
            get { lock (_lock) return _ended; }
        }

        /// <summary>Ends the turn; true when this call ended it.</summary>
        public bool End()
        {
            bool first, release;
            lock (_lock)
            {
                first = !_ended;
                _ended = true;
                release = ReleaseDue();
            }
            if (release) gate.Release();
            return first;
        }

        internal bool TryBegin()
        {
            lock (_lock)
            {
                if (_ended) return false;
                _running++;
                return true;
            }
        }

        internal void Finish()
        {
            bool release;
            lock (_lock)
            {
                _running--;
                release = ReleaseDue();
            }
            if (release) gate.Release();
        }

        private bool ReleaseDue()
        {
            if (!_ended || _running > 0 || _released) return false;
            _released = true;
            return true;
        }
    }
}

/// <summary>Marks a GET endpoint that changes state, so it runs under the request gate.</summary>
public sealed class ChangesState
{
    public static readonly ChangesState Instance = new();
}

public static class ChangesStateExtensions
{
    public static TBuilder ChangesState<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder =>
        builder.WithMetadata(Auth.ChangesState.Instance);
}

public sealed class RequestGateMiddleware(RequestDelegate next, RequestGate gate, SecurityOptions options)
{
    public async Task InvokeAsync(HttpContext ctx)
    {
        if (!RequestGate.Covers(ctx))
        {
            await next(ctx);
            return;
        }

        // The client paces its upload and its download, so neither happens in the request's turn. The body is read
        // before authentication, so its size is checked first.
        var client = ctx.RequestAborted;
        var limit = RequestGate.BodyLimit(ctx);
        if (ctx.Request.ContentLength > limit)
        {
            await TooLarge(ctx, limit);
            return;
        }
        ctx.Request.EnableBuffering();
        try
        {
            await ctx.Request.Body.DrainAsync(limit, client);
        }
        catch (InvalidDataException)
        {
            await TooLarge(ctx, limit);
            return;
        }
        ctx.Request.Body.Position = 0;
        var responseBody = ctx.Features.Get<IHttpResponseBodyFeature>()!;
        await using var buffered = new FileBufferingWriteStream();
        var bufferedBody = new StreamResponseBodyFeature(buffered, responseBody);
        var headers = ctx.Response.Headers.ToList();

        await gate.WaitAsync(client);
        var turn = new RequestGate.Turn(gate);
        var late = false;
        try
        {
            // At the deadline the turn ends before the work is told to stop, so whatever the stop causes is late.
            using var work = CancellationTokenSource.CreateLinkedTokenSource(client);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(options.StateChangeSeconds));
            using var ends = deadline.Token.Register(() =>
            {
                turn.End();
                work.Cancel();
            });
            ctx.RequestAborted = work.Token;
            ctx.Features.Set<IHttpResponseBodyFeature>(bufferedBody);
            ctx.Features.Set(turn);
            Exception? failure = null;
            try
            {
                await next(ctx);
                await bufferedBody.CompleteAsync();
            }
            catch (Exception e)
            {
                failure = e;
            }
            late = !turn.End() && !client.IsCancellationRequested;
            if (failure is not null && !late) ExceptionDispatchInfo.Throw(failure);
        }
        finally
        {
            turn.End();
            ctx.Features.Set(responseBody);
            ctx.RequestAborted = client;
        }

        if (late)
        {
            ctx.Response.Headers.Clear();
            foreach (var (name, value) in headers) ctx.Response.Headers[name] = value;
            await Results.Problem(title: "The change did not finish in time",
                detail: $"It was stopped after {options.StateChangeSeconds} seconds and may have partly applied; the audit log shows what was recorded.",
                statusCode: StatusCodes.Status503ServiceUnavailable).ExecuteAsync(ctx);
            return;
        }
        await buffered.DrainBufferAsync(responseBody.Stream, client);
    }

    private static Task TooLarge(HttpContext ctx, long limit) =>
        Results.Problem(title: "Too large",
            detail: limit % (1024 * 1024) == 0
                ? $"This request's body is at most {limit / (1024 * 1024)} MiB."
                : $"This request's body is at most {limit / 1024} KiB.",
            statusCode: StatusCodes.Status413PayloadTooLarge).ExecuteAsync(ctx);
}

/// <summary>
/// Refuses a database write made for a request that does not hold the request gate, apart from authentication's own
/// bookkeeping (last use, revoking a session whose user's role changed), and any write or commit after the request's
/// turn has ended. A write or commit under way when the turn ends keeps the gate until it finishes. Work outside a
/// request writes freely.
/// </summary>
public sealed partial class RequestWriteGuard(IHttpContextAccessor accessor) : DbCommandInterceptor, IDbTransactionInterceptor
{
    private static readonly AsyncLocal<bool> Authenticating = new();
    private readonly ConcurrentDictionary<Guid, RequestGate.Turn> _running = new();

    /// <summary>Allows writes for the rest of the calling async method; the flag does not flow back to its caller.</summary>
    public static void AllowAuthenticationWrites() => Authenticating.Value = true;

    public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData,
        InterceptionResult<DbDataReader> result)
    {
        Begin(eventData.CommandId, command.CommandText);
        return result;
    }

    public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
    {
        Begin(eventData.CommandId, command.CommandText);
        return ValueTask.FromResult(result);
    }

    public override InterceptionResult<int> NonQueryExecuting(DbCommand command, CommandEventData eventData,
        InterceptionResult<int> result)
    {
        Begin(eventData.CommandId, command.CommandText);
        return result;
    }

    public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        Begin(eventData.CommandId, command.CommandText);
        return ValueTask.FromResult(result);
    }

    public override InterceptionResult<object> ScalarExecuting(DbCommand command, CommandEventData eventData,
        InterceptionResult<object> result)
    {
        Begin(eventData.CommandId, command.CommandText);
        return result;
    }

    public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
    {
        Begin(eventData.CommandId, command.CommandText);
        return ValueTask.FromResult(result);
    }

    public override DbDataReader ReaderExecuted(DbCommand command, CommandExecutedEventData eventData, DbDataReader result)
    {
        Finish(eventData.CommandId);
        return result;
    }

    public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
        DbDataReader result, CancellationToken cancellationToken = default)
    {
        Finish(eventData.CommandId);
        return ValueTask.FromResult(result);
    }

    public override int NonQueryExecuted(DbCommand command, CommandExecutedEventData eventData, int result)
    {
        Finish(eventData.CommandId);
        return result;
    }

    public override ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
        int result, CancellationToken cancellationToken = default)
    {
        Finish(eventData.CommandId);
        return ValueTask.FromResult(result);
    }

    public override object? ScalarExecuted(DbCommand command, CommandExecutedEventData eventData, object? result)
    {
        Finish(eventData.CommandId);
        return result;
    }

    public override ValueTask<object?> ScalarExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
        object? result, CancellationToken cancellationToken = default)
    {
        Finish(eventData.CommandId);
        return ValueTask.FromResult(result);
    }

    public override void CommandFailed(DbCommand command, CommandErrorEventData eventData) => Finish(eventData.CommandId);

    public override Task CommandFailedAsync(DbCommand command, CommandErrorEventData eventData,
        CancellationToken cancellationToken = default)
    {
        Finish(eventData.CommandId);
        return Task.CompletedTask;
    }

    public override void CommandCanceled(DbCommand command, CommandEndEventData eventData) => Finish(eventData.CommandId);

    public override Task CommandCanceledAsync(DbCommand command, CommandEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        Finish(eventData.CommandId);
        return Task.CompletedTask;
    }

    public InterceptionResult TransactionCommitting(DbTransaction transaction, TransactionEventData eventData,
        InterceptionResult result)
    {
        Begin(eventData.TransactionId, sql: null);
        return result;
    }

    public ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,
        TransactionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
    {
        Begin(eventData.TransactionId, sql: null);
        return ValueTask.FromResult(result);
    }

    public void TransactionCommitted(DbTransaction transaction, TransactionEndEventData eventData) =>
        Finish(eventData.TransactionId);

    public Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        Finish(eventData.TransactionId);
        return Task.CompletedTask;
    }

    public void TransactionFailed(DbTransaction transaction, TransactionErrorEventData eventData) =>
        Finish(eventData.TransactionId);

    public Task TransactionFailedAsync(DbTransaction transaction, TransactionErrorEventData eventData,
        CancellationToken cancellationToken = default)
    {
        Finish(eventData.TransactionId);
        return Task.CompletedTask;
    }

    // A null sql is a commit.
    private void Begin(Guid id, string? sql)
    {
        if (sql is not null && !Write().IsMatch(sql)) return;
        if (accessor.HttpContext is not { } ctx) return;
        if (ctx.Features.Get<RequestGate.Turn>() is { } turn)
        {
            if (!turn.TryBegin())
                throw new InvalidOperationException(
                    $"{ctx.Request.Method} {ctx.Request.Path} {(sql is null ? "committed" : "wrote")} to the database after its turn at the request gate ended.");
            _running[id] = turn;
            return;
        }
        if (sql is null || Authenticating.Value) return;
        throw new InvalidOperationException(
            $"{ctx.Request.Method} {ctx.Request.Path} wrote to the database outside the request gate.");
    }

    private void Finish(Guid id)
    {
        if (_running.TryRemove(id, out var turn)) turn.Finish();
    }

    [GeneratedRegex(@"^\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", RegexOptions.IgnoreCase | RegexOptions.Multiline)]
    private static partial Regex Write();
}
