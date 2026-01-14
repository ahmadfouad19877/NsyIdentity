using Microsoft.AspNetCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;

public sealed class RequireDeviceHeadersOnTokenRequestHandler
    : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenRequestContext>
{
    public ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenRequestContext context)
    {
        var http = context.Transaction.GetHttpRequest()?.HttpContext;
        if (http is null) return ValueTask.CompletedTask;

        var deviceId = http.Request.Headers["X-Device-Id"].ToString();
        var deviceName = http.Request.Headers["X-Device-Name"].ToString();
        var platform = http.Request.Headers["X-Platform"].ToString();

        if (string.IsNullOrWhiteSpace(deviceId) ||
            string.IsNullOrWhiteSpace(deviceName) ||
            string.IsNullOrWhiteSpace(platform))
        {
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidRequest,
                description: "Missing required device headers: X-Device-Id, X-Device-Name, X-Platform.");
        }

        return ValueTask.CompletedTask;
    }
}