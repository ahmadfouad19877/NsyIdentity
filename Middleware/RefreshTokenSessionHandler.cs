using IdentityServer.Models;
using Microsoft.AspNetCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace IdentityServer.OpenIddict.Handlers;

public sealed class RefreshTokenSessionHandler : IOpenIddictServerHandler<ApplyTokenResponseContext>
{
    public async ValueTask HandleAsync(ApplyTokenResponseContext context)
    {
        // ✅ لو ما في refresh_token بالرد، ما في شي نحدثه
        var refreshTokenValue = context.Response.RefreshToken;
        if (string.IsNullOrWhiteSpace(refreshTokenValue))
            return;

        // ✅ HttpContext
        var http = context.Transaction.GetHttpRequest()?.HttpContext;
        if (http is null)
            return;

        // ✅ Device headers
        var deviceId   = http.Request.Headers["X-Device-Id"].ToString();
        var deviceName = http.Request.Headers["X-Device-Name"].ToString();
        var platform   = http.Request.Headers["X-Platform"].ToString();

        if (string.IsNullOrWhiteSpace(deviceId) ||
            string.IsNullOrWhiteSpace(deviceName) ||
            string.IsNullOrWhiteSpace(platform))
            return;

        deviceId = deviceId.Trim();
        deviceName = deviceName.Trim();
        platform = platform.Trim();

        using var scope = http.RequestServices.CreateScope();

        var db = scope.ServiceProvider.GetRequiredService<ApplicationDb>();
        var tokenManager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // ✅ 1) جيب token entity من قيمة refresh_token (ReferenceId)
        var token = await tokenManager.FindByReferenceIdAsync(refreshTokenValue);
        if (token is null)
            return;

        // ✅ 2) TokenId الحقيقي (للتخزين بجدول الجلسات)
        var tokenId = await tokenManager.GetIdAsync(token);
        if (string.IsNullOrWhiteSpace(tokenId))
            return;

        // ✅ 3) UserId من داخل التوكن (sub)
        var userId = await tokenManager.GetSubjectAsync(token);
        if (string.IsNullOrWhiteSpace(userId))
            return;

        // ✅ 4) ClientId: نجيبه من ApplicationId المخزن على التوكن ثم نحوله لـ ClientId
        string? clientId = null;

        var appId = await tokenManager.GetApplicationIdAsync(token);
        if (!string.IsNullOrWhiteSpace(appId))
        {
            var app = await appManager.FindByIdAsync(appId);
            if (app is not null)
                clientId = await appManager.GetClientIdAsync(app);
        }

        // ✅ fallback: أحيانًا يكون موجود بالـ request
        clientId ??= context.Request?.ClientId;

        if (string.IsNullOrWhiteSpace(clientId))
            return;

        // ✅ 5) Upsert Session (UserId + ClientId + DeviceId)
        var session = await db.UserSessions.FirstOrDefaultAsync(x =>
            x.UserId == userId &&
            x.ClientId == clientId &&
            x.DeviceId == deviceId &&
            x.IsActive &&
            !x.IsRevoked);

        if (session is null)
        {
            session = new ApplicationUserSessions
            {
                UserId = userId,
                ClientId = clientId,
                DeviceId = deviceId,
                DeviceName = deviceName,
                Platform = platform,
                IpAddress = http.Connection.RemoteIpAddress?.ToString(),
                UserAgent = http.Request.Headers.UserAgent.ToString(),
                CreatedAt = DateTime.UtcNow,
                LastSeenAt = DateTime.UtcNow,
                IsActive = true,
                IsRevoked = false
            };

            db.UserSessions.Add(session);
        }

        // ✅ 6) تحديث RefreshTokenId (TokenId) عند كل Login/Refresh Rotation
        session.TokenId = tokenId;
        session.LastSeenAt = DateTime.UtcNow;

        await db.SaveChangesAsync();
    }
}
