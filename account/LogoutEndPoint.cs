using System.Security.Claims;
using IdentityServerNSY.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace IdentityServerNSY.account;

public static class LogoutEndPoint
{
    public static void MapLogoutEndPoint(this WebApplication app)
    {
        // =========================================================
        // Logout current device
        // تسجيل خروج من الجهاز الحالي
        // =========================================================
        app.MapPost("/account/logout", async (HttpContext http, ApplicationDb db) =>
        {
            var userId =
                http.User.FindFirstValue(OpenIddictConstants.Claims.Subject) ??
                http.User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrWhiteSpace(userId))
                return Results.Unauthorized();

            var clientId = http.User.FindFirstValue("azp");
            if (string.IsNullOrWhiteSpace(clientId))
            {
                return Results.BadRequest(new
                {
                    error = "missing_client",
                    error_description = "azp claim is missing."
                });
            }

            var deviceId = http.Request.Headers["X-Device-Id"].ToString();
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                return Results.BadRequest(new
                {
                    error = "missing_device",
                    error_description = "X-Device-Id header is required."
                });
            }

            var session = await db.UserSessions
                .FirstOrDefaultAsync(x =>
                    x.UserId == userId &&
                    x.ClientId == clientId &&
                    x.DeviceId == deviceId &&
                    x.IsActive &&
                    !x.IsRevoked);

            var now = DateTime.UtcNow;

            if (session != null)
            {
                session.IsActive = false;
                session.IsRevoked = true;
                session.RevokedAt = now;
                session.LastSeenAt = now;

                await db.SaveChangesAsync();
            }

            // عربي: حذف Session الخاصة بالـ ASP.NET
            // English: Clear ASP.NET session
            http.Session.Clear();

            // عربي: تسجيل خروج من كوكي Identity
            // English: Sign out from Identity cookie
            await http.SignOutAsync(IdentityConstants.ApplicationScheme);

            AddNoCacheHeaders(http);

            return Results.Ok(new
            {
                message = session == null
                    ? "Already logged out."
                    : "Logged out from this device."
            });
        }).RequireAuthorization();

        // =========================================================
        // Logout all devices
        // تسجيل خروج من كل الأجهزة
        // =========================================================
        app.MapPost("/account/logout-all", async (HttpContext http, ApplicationDb db) =>
        {
            var userId =
                http.User.FindFirstValue(OpenIddictConstants.Claims.Subject) ??
                http.User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrWhiteSpace(userId))
                return Results.Unauthorized();

            var now = DateTime.UtcNow;

            var sessions = await db.UserSessions
                .Where(x => x.UserId == userId && x.IsActive && !x.IsRevoked)
                .ToListAsync();

            foreach (var s in sessions)
            {
                s.IsActive = false;
                s.IsRevoked = true;
                s.RevokedAt = now;
                s.LastSeenAt = now;
            }

            await db.SaveChangesAsync();

            // عربي: حذف جلسة المتصفح الحالي أيضاً
            // English: Also sign out current browser session
            http.Session.Clear();
            await http.SignOutAsync(IdentityConstants.ApplicationScheme);

            AddNoCacheHeaders(http);

            return Results.Ok(new
            {
                message = sessions.Count == 0
                    ? "No active sessions."
                    : "Logged out from all devices."
            });
        }).RequireAuthorization();

        // =========================================================
        // OpenIddict end-session endpoint
        // هذا هو الرابط القياسي للـ logout عبر OpenIddict
        // =========================================================
        app.MapMethods("/connect/logout", new[] { "GET", "POST" }, async (HttpContext http, ApplicationDb db) =>
        {
            var userId =
                http.User.FindFirstValue(OpenIddictConstants.Claims.Subject) ??
                http.User.FindFirstValue(ClaimTypes.NameIdentifier);

            string? clientId = http.Request.Query["client_id"].ToString();
            if (string.IsNullOrWhiteSpace(clientId))
            {
                clientId = http.User.FindFirstValue("azp");
            }

            var deviceId = http.Request.Headers["X-Device-Id"].ToString();

            // عربي: إذا عرفنا المستخدم والعميل والجهاز، نلغي جلسة هذا الجهاز
            // English: If user/client/device are known, revoke that device session
            if (!string.IsNullOrWhiteSpace(userId) &&
                !string.IsNullOrWhiteSpace(clientId) &&
                !string.IsNullOrWhiteSpace(deviceId))
            {
                var session = await db.UserSessions
                    .FirstOrDefaultAsync(x =>
                        x.UserId == userId &&
                        x.ClientId == clientId &&
                        x.DeviceId == deviceId &&
                        x.IsActive &&
                        !x.IsRevoked);

                if (session != null)
                {
                    var now = DateTime.UtcNow;
                    session.IsActive = false;
                    session.IsRevoked = true;
                    session.RevokedAt = now;
                    session.LastSeenAt = now;

                    await db.SaveChangesAsync();
                }
            }

            // عربي: حذف جلسة ASP.NET والكوكي
            // English: Clear ASP.NET session and auth cookie
            http.Session.Clear();
            await http.SignOutAsync(IdentityConstants.ApplicationScheme);

            AddNoCacheHeaders(http);

            var postLogoutRedirectUri = http.Request.Query["post_logout_redirect_uri"].ToString();

            if (!string.IsNullOrWhiteSpace(postLogoutRedirectUri))
            {
                return Results.Redirect(postLogoutRedirectUri);
            }

            return Results.Redirect("/logout-success");
        }).AllowAnonymous();

        // =========================================================
        // Optional browser logout helper
        // مساعد بسيط إذا أردت endpoint داخلي مستقل
        // =========================================================
        app.MapPost("/account/logoutcode", async (HttpContext http) =>
        {
            http.Session.Clear();
            await http.SignOutAsync(IdentityConstants.ApplicationScheme);

            AddNoCacheHeaders(http);

            return Results.Ok(new
            {
                message = "Browser session cleared successfully."
            });
        }).AllowAnonymous();

        // =========================================================
        // Success page
        // صفحة نجاح بعد تسجيل الخروج
        // =========================================================
        app.MapGet("/logout-success", () =>
            Results.Content("""
                            <html>
                              <body style="font-family:Arial;padding:30px">
                                <h3>Logged out successfully 🔐</h3>
                                <p>You can close this page now.</p>
                              </body>
                            </html>
                            """, "text/html")
        ).AllowAnonymous();
    }

    // =========================================================
    // Helpers
    // =========================================================
    private static void AddNoCacheHeaders(HttpContext http)
    {
        http.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        http.Response.Headers.Pragma = "no-cache";
        http.Response.Headers.Expires = "0";
    }
}