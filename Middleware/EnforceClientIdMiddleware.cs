namespace IdentityServer.Middleware;

public class EnforceClientIdMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _requiredClientId;

    public EnforceClientIdMiddleware(RequestDelegate next, string requiredClientId)
    {
        _next = next;
        _requiredClientId = requiredClientId;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // تأكد أن التوكن مفعّل
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var clientId = context.User.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value;
            Console.WriteLine($"Enforcing client ID: {clientId}");
            if (clientId == null || clientId != _requiredClientId)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("Forbidden: Invalid client_id");
                return;
            }
        }

        await _next(context);
    }
}