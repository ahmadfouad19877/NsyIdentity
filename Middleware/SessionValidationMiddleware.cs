using System.Security.Claims;
using IdentityServer.Models;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace IdentityServer.Middleware;

public sealed class SessionValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SessionValidationOptions _options;

    public SessionValidationMiddleware(RequestDelegate next, SessionValidationOptions options)
    {
        _next = next;
        _options = options;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";

        // ✅ تجاهل paths المستثناة
        if (IsSkippedPath(path))
        {
            await _next(context);
            return;
        }

        // ✅ (جديد) إلزام Headers على كل /api/* حتى لو Anonymous
        if (_options.EnforceDeviceHeadersOnApiPaths &&
            path.StartsWith(_options.ApiPrefix, StringComparison.OrdinalIgnoreCase))
        {
            if (!TryReadDeviceHeaders(context, out var deviceId, out var deviceName, out var platform, out var error, out var desc))
            {
                await Reject(context, error, desc);
                return;
            }
        }

        // ✅ فقط إذا المستخدم Authenticated (Token Valid) نفحص Session من DB
        if (context.User?.Identity?.IsAuthenticated != true)
        {
            await _next(context);
            return;
        }

        // ✅ استخراج userId + clientId
        var userId =
            context.User.FindFirstValue(OpenIddictConstants.Claims.Subject) ??
            context.User.FindFirstValue(ClaimTypes.NameIdentifier);

        var clientId = context.User.FindFirstValue("azp");

        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(clientId))
        {
            await Reject(context, "invalid_token", "Missing required claims (sub/azp).");
            return;
        }

        // ✅ Headers (مطلوبة أيضًا هنا) + نستخدمها للتحقق من session
        if (!TryReadDeviceHeaders(context, out var deviceId2, out _, out _, out var error2, out var desc2))
        {
            await Reject(context, error2, desc2);
            return;
        }

        using var scope = context.RequestServices.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDb>();

        var ok = await db.UserSessions.AnyAsync(x =>
            x.UserId == userId &&
            x.ClientId == clientId &&
            x.DeviceId == deviceId2 &&
            x.IsActive &&
            !x.IsRevoked);

        if (!ok)
        {
            await Reject(context, "session_revoked", "This session is revoked or inactive. Please login again.");
            return;
        }

        if (_options.UpdateLastSeen)
        {
            await db.UserSessions
                .Where(x =>
                    x.UserId == userId &&
                    x.ClientId == clientId &&
                    x.DeviceId == deviceId2 &&
                    x.IsActive &&
                    !x.IsRevoked)
                .ExecuteUpdateAsync(s => s.SetProperty(p => p.LastSeenAt, DateTime.UtcNow));
        }

        await _next(context);
    }

    private bool TryReadDeviceHeaders(
        HttpContext context,
        out string deviceId,
        out string deviceName,
        out string platform,
        out string error,
        out string description)
    {
        deviceId = context.Request.Headers[_options.DeviceIdHeader].ToString();
        deviceName = context.Request.Headers[_options.DeviceNameHeader].ToString();
        platform = context.Request.Headers[_options.PlatformHeader].ToString();

        if (string.IsNullOrWhiteSpace(deviceId))
        {
            error = "missing_device";
            description = $"{_options.DeviceIdHeader} header is required.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(deviceName))
        {
            error = "missing_device_name";
            description = $"{_options.DeviceNameHeader} header is required.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(platform))
        {
            error = "missing_platform";
            description = $"{_options.PlatformHeader} header is required.";
            return false;
        }

        // ✅ تنظيف (مستحسن)
        deviceId = deviceId.Trim();
        deviceName = deviceName.Trim();
        platform = platform.Trim();

        error = "";
        description = "";
        return true;
    }

    private static async Task Reject(HttpContext context, string error, string description)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";

        await context.Response.WriteAsJsonAsync(new
        {
            error,
            error_description = description
        });
    }
    private bool IsSkippedPath(string path)
    {
        foreach (var p in _options.SkipPaths)
        {
            if (string.Equals(p, "/", StringComparison.Ordinal))
            {
                if (string.Equals(path, "/", StringComparison.Ordinal))
                    return true;

                continue;
            }

            if (path.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

}

public sealed class SessionValidationOptions
{
    public string DeviceIdHeader { get; set; } = "X-Device-Id";
    public string DeviceNameHeader { get; set; } = "X-Device-Name";
    public string PlatformHeader { get; set; } = "X-Platform";

    public bool UpdateLastSeen { get; set; } = true;

    // ✅ (جديد) إجبار الهيدرز على /api/*
    public bool EnforceDeviceHeadersOnApiPaths { get; set; } = true;
    public string ApiPrefix { get; set; } = "/api";

    public string[] SkipPaths { get; set; } = new[]
    {
        "/",
        "/account/login",
        "/connect/authorize",
        "/connect/token",
        "/connect/intros",
        "/swagger",
        "/favicon.ico"
    };
}
