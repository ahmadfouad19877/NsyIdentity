using IdentityServer.Models;
using Microsoft.AspNetCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;

public sealed class StoreSessionOnTokenHandler
    : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessSignInContext>
{
    private readonly ApplicationDb _db;

    public StoreSessionOnTokenHandler(ApplicationDb db) => _db = db;

    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessSignInContext context)
    {
        var http = context.Transaction.GetHttpRequest()?.HttpContext;
        if (http is null) return;

        var request = http.GetOpenIddictServerRequest();
        if (request is null) return;

        // ✅ هذا يضمن أننا في /connect/token (لأن grant_type موجود)
        if (string.IsNullOrWhiteSpace(request.GrantType))
            return;

        // ✅ أنت تدعم AuthorizationCode + Refresh
        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            return;

        var principal = context.Principal;
        if (principal is null) return;

        // ✅ userId
        var userId = principal.GetClaim(OpenIddictConstants.Claims.Subject);
        if (string.IsNullOrWhiteSpace(userId)) return;

        // ✅ clientId (azp)
        var clientId = principal.GetClaim("azp") ?? request.ClientId;
        if (string.IsNullOrWhiteSpace(clientId)) return;

        // ✅ device claims القادمة من authorize/code
        var codeDeviceId = principal.GetClaim("device_id");
        var codeDeviceName = principal.GetClaim("device_name");
        var codePlatform = principal.GetClaim("platform");

        // ✅ headers القادمة على /connect/token
        var headerDeviceId = http.Request.Headers["X-Device-Id"].ToString();
        var headerDeviceName = http.Request.Headers["X-Device-Name"].ToString();
        var headerPlatform = http.Request.Headers["X-Platform"].ToString();

        // لازم يكون device_id موجود داخل الكود (لأن authorize فرضناه)
        if (string.IsNullOrWhiteSpace(codeDeviceId))
        {
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidGrant,
                description: "Missing device_id in authorization code.");
            return;
        }

        // ✅ تطابق جهاز الكود مع جهاز التوكن
        if (!string.Equals(codeDeviceId, headerDeviceId, StringComparison.Ordinal))
        {
            Console.WriteLine(string.Equals(codeDeviceId, headerDeviceId, StringComparison.Ordinal));
            Console.WriteLine(codeDeviceId);
            
            Console.WriteLine(headerDeviceId);
            Console.WriteLine(headerDeviceName);
            Console.WriteLine(headerPlatform);
            context.Reject(
                error: OpenIddictConstants.Errors.InvalidGrant,
                description: "Device mismatch between authorization and token request.");
            return;
        }

        // نختار الاسم/المنصة من الكود أولاً، وإلا من الهيدر
        var finalDeviceName = !string.IsNullOrWhiteSpace(codeDeviceName) ? codeDeviceName : headerDeviceName;
        var finalPlatform = !string.IsNullOrWhiteSpace(codePlatform) ? codePlatform : headerPlatform;

        var ip = http.Connection.RemoteIpAddress?.ToString();
        var userAgent = http.Request.Headers.UserAgent.ToString();

        // ✅ Upsert session (مفتاح منطقي: UserId + ClientId + DeviceId)
        var session = await _db.UserSessions
            .FirstOrDefaultAsync(x =>
                x.UserId == userId &&
                x.ClientId == clientId &&
                x.DeviceId == headerDeviceId);

        if (session is null)
        {
            session = new ApplicationUserSessions
            {
                UserId = userId,
                ClientId = clientId,
                DeviceId = headerDeviceId,
                DeviceName = finalDeviceName,
                Platform = finalPlatform,
                IpAddress = ip,
                UserAgent = userAgent,
                IsActive = true,
                IsRevoked = false,
                CreatedAt = DateTime.UtcNow,
                LastSeenAt = DateTime.UtcNow,
                TokenId = null,
                RevokedAt = default // (الأفضل تكون Nullable بالـ Entity)
            };

            _db.UserSessions.Add(session);
        }
        else
        {
            session.DeviceName = string.IsNullOrWhiteSpace(finalDeviceName) ? session.DeviceName : finalDeviceName;
            session.Platform = string.IsNullOrWhiteSpace(finalPlatform) ? session.Platform : finalPlatform;
            session.IpAddress = ip;
            session.UserAgent = userAgent;

            session.IsActive = true;
            session.IsRevoked = false;
            session.LastSeenAt = DateTime.UtcNow;
        }

        await _db.SaveChangesAsync();
    }
}
