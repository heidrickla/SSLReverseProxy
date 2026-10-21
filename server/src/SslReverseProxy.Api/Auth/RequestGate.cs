using System.Data.Common;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace SslReverseProxy.Api.Auth;

/// <summary>
/// Runs state-changing requests one at a time, from before authentication through the effect and its audit row, so
/// a change to who may do what lands wholly before or wholly after each of them. Reads and the event stream stay
/// outside. The process is the only writer of its database, so one in-process gate covers every request.
/// </summary>
public sealed class RequestGate
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    public Task WaitAsync(CancellationToken ct) => _gate.WaitAsync(ct);

    public void Release() => _gate.Release();

    /// <summary>Every method but GET, HEAD and OPTIONS, and any endpoint marked with <see cref="ChangesState"/>.</summary>
    public static bool Covers(HttpContext ctx) =>
        !(HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsHead(ctx.Request.Method)
            || HttpMethods.IsOptions(ctx.Request.Method))
        || ctx.GetEndpoint()?.Metadata.GetMetadata<ChangesState>() is not null;

    public static bool Holds(HttpContext ctx) => ctx.Features.Get<Held>() is not null;

    internal sealed class Held
    {
        public static readonly Held Instance = new();
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

public sealed class RequestGateMiddleware(RequestDelegate next, RequestGate gate)
{
    public async Task InvokeAsync(HttpContext ctx)
    {
        if (!RequestGate.Covers(ctx))
        {
            await next(ctx);
            return;
        }
        await gate.WaitAsync(ctx.RequestAborted);
        ctx.Features.Set(RequestGate.Held.Instance);
        try
        {
            await next(ctx);
        }
        finally
        {
            ctx.Features.Set<RequestGate.Held?>(null);
            gate.Release();
        }
    }
}

/// <summary>
/// Refuses a database write made for a request that does not hold the request gate, apart from authentication's own
/// bookkeeping (last use, revoking a session whose user's role changed). Work outside a request writes freely.
/// </summary>
public sealed partial class RequestWriteGuard(IHttpContextAccessor accessor) : DbCommandInterceptor
{
    private static readonly AsyncLocal<bool> Authenticating = new();

    /// <summary>Allows writes for the rest of the calling async method; the flag does not flow back to its caller.</summary>
    public static void AllowAuthenticationWrites() => Authenticating.Value = true;

    public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData,
        InterceptionResult<DbDataReader> result)
    {
        Check(command);
        return result;
    }

    public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
    {
        Check(command);
        return ValueTask.FromResult(result);
    }

    public override InterceptionResult<int> NonQueryExecuting(DbCommand command, CommandEventData eventData,
        InterceptionResult<int> result)
    {
        Check(command);
        return result;
    }

    public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        Check(command);
        return ValueTask.FromResult(result);
    }

    public override InterceptionResult<object> ScalarExecuting(DbCommand command, CommandEventData eventData,
        InterceptionResult<object> result)
    {
        Check(command);
        return result;
    }

    public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command,
        CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
    {
        Check(command);
        return ValueTask.FromResult(result);
    }

    private void Check(DbCommand command)
    {
        if (accessor.HttpContext is not { } ctx || RequestGate.Holds(ctx) || Authenticating.Value) return;
        if (Write().IsMatch(command.CommandText))
            throw new InvalidOperationException(
                $"{ctx.Request.Method} {ctx.Request.Path} wrote to the database outside the request gate.");
    }

    [GeneratedRegex(@"^\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", RegexOptions.IgnoreCase | RegexOptions.Multiline)]
    private static partial Regex Write();
}
