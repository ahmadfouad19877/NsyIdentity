using System.Security.Claims;
using IdentityServer.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace IdentityServerNSY.account;

public static class LogoutEndPoint
{
    public static void MapLogoutEndPoint(this WebApplication app)
    {
        app.MapPost("/account/logout", async (HttpContext http, ApplicationDb db) =>
        {
            var userId = http.User.FindFirstValue(OpenIddictConstants.Claims.Subject)
                         ?? http.User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrWhiteSpace(userId))
                return Results.Unauthorized();

            var clientId = http.User.FindFirstValue("azp");
            if (string.IsNullOrWhiteSpace(clientId))
                return Results.BadRequest(new { error = "missing_client", error_description = "azp claim is missing." });

            var deviceId = http.Request.Headers["X-Device-Id"].ToString();
            if (string.IsNullOrWhiteSpace(deviceId))
                return Results.BadRequest(new { error = "missing_device", error_description = "X-Device-Id header is required." });

            var session = await db.UserSessions
                .FirstOrDefaultAsync(x =>
                    x.UserId == userId &&
                    x.ClientId == clientId &&
                    x.DeviceId == deviceId &&
                    x.IsActive &&
                    !x.IsRevoked);

            if (session == null)
                return Results.Ok(new { message = "Already logged out." });

            var now = DateTime.UtcNow;
            session.IsActive = false;
            session.IsRevoked = true;
            session.RevokedAt = now; // إذا خليتها DateTime? ممتاز
            session.LastSeenAt = now;

            await db.SaveChangesAsync();

            return Results.Ok(new { message = "Logged out from this device." });

        }).RequireAuthorization();

        
        app.MapPost("/account/logout-all", async (HttpContext http, ApplicationDb db) =>
        {
            var userId = http.User.FindFirstValue(OpenIddictConstants.Claims.Subject)
                         ?? http.User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrWhiteSpace(userId))
                return Results.Unauthorized();

            var now = DateTime.UtcNow;

            var sessions = await db.UserSessions
                .Where(x => x.UserId == userId && x.IsActive && !x.IsRevoked)
                .ToListAsync();

            if (sessions.Count == 0)
                return Results.Ok(new { message = "No active sessions." });

            foreach (var s in sessions)
            {
                s.IsActive = false;
                s.IsRevoked = true;
                s.RevokedAt = now;
                s.LastSeenAt = now;
            }

            await db.SaveChangesAsync();

            return Results.Ok(new { message = "Logged out from all devices." });

        }).RequireAuthorization();
        
        
        app.MapPost("/account/logoutcode", async (HttpContext ctx) =>
        {
            ctx.Session?.Clear();

            // أهم سطر: سجّل خروج الكوكي تبع تسجيل الدخول
            await ctx.SignOutAsync(IdentityConstants.ApplicationScheme);

            return Results.Ok();
        }).AllowAnonymous();
        
        app.MapGet("/logout-success", () =>
            Results.Content("""
                            <html><body style="font-family:Arial;padding:30px">
                              <h3>Logged out successfully 🔐</h3>
                              <p>You can close this page now.</p>
                            </body></html>
                            """, "text/html")
        ).AllowAnonymous();


    }
}