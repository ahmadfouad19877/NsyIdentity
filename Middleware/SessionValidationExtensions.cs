namespace IdentityServer.Middleware;

public static class SessionValidationExtensions
{
    public static IApplicationBuilder UseSessionValidation(
        this IApplicationBuilder app,
        Action<SessionValidationOptions>? configure = null)
    {
        var options = new SessionValidationOptions();
        configure?.Invoke(options);

        return app.UseMiddleware<SessionValidationMiddleware>(options);
    }
}