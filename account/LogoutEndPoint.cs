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
        <!DOCTYPE html>
        <html lang="ar" dir="rtl">
        <head>
            <meta charset="UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>Logout Success</title>
        </head>
        <body style="
            margin:0;
            padding:0;
            font-family:Arial, Helvetica, sans-serif;
            background:linear-gradient(135deg, #0f172a 0%, #111827 45%, #1e293b 100%);
            min-height:100vh;
            display:flex;
            align-items:center;
            justify-content:center;
        ">
            <div style="
                width:100%;
                max-width:460px;
                margin:24px;
                background:rgba(255,255,255,0.96);
                border:1px solid rgba(255,255,255,0.25);
                border-radius:24px;
                box-shadow:0 20px 60px rgba(0,0,0,0.28);
                overflow:hidden;
            ">
                <div style="
                    height:8px;
                    background:linear-gradient(90deg, #16a34a 0%, #22c55e 50%, #86efac 100%);
                "></div>

                <div style="padding:36px 30px 30px 30px; text-align:center;">
                    <div style="
                        width:84px;
                        height:84px;
                        margin:0 auto 22px auto;
                        border-radius:50%;
                        background:linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
                        display:flex;
                        align-items:center;
                        justify-content:center;
                        box-shadow:inset 0 0 0 1px rgba(34,197,94,0.18);
                    ">
                        <div style="
                            width:52px;
                            height:52px;
                            border-radius:50%;
                            background:#16a34a;
                            color:white;
                            display:flex;
                            align-items:center;
                            justify-content:center;
                            font-size:28px;
                            font-weight:bold;
                        ">✓</div>
                    </div>

                    <div style="
                        display:inline-block;
                        padding:6px 14px;
                        border-radius:999px;
                        background:#f0fdf4;
                        color:#166534;
                        font-size:12px;
                        font-weight:bold;
                        letter-spacing:0.3px;
                        margin-bottom:18px;
                    ">
                        SESSION CLOSED
                    </div>

                    <h1 style="
                        margin:0 0 14px 0;
                        font-size:28px;
                        color:#0f172a;
                        line-height:1.4;
                    ">
                        تم تسجيل الخروج بنجاح
                    </h1>

                    <p style="
                        margin:0 0 10px 0;
                        font-size:16px;
                        color:#334155;
                        line-height:1.9;
                    ">
                        لقد قمت بتسجيل الخروج ومغادرة المنصة بشكل آمن وناجح.
                    </p>

                    <p style="
                        margin:0 0 26px 0;
                        font-size:14px;
                        color:#64748b;
                        line-height:1.8;
                    ">
                        يمكنك الآن إغلاق هذه الصفحة أو العودة للمتابعة عند الحاجة.
                    </p>

                    <div style="
                        background:#f8fafc;
                        border:1px solid #e2e8f0;
                        border-radius:16px;
                        padding:14px 16px;
                        text-align:right;
                        margin-bottom:24px;
                    ">
                        <div style="
                            font-size:13px;
                            color:#0f172a;
                            font-weight:bold;
                            margin-bottom:6px;
                        ">
                            ملاحظة أمان
                        </div>
                        <div style="
                            font-size:13px;
                            color:#475569;
                            line-height:1.8;
                        ">
                            تم إنهاء الجلسة الحالية بنجاح. للحفاظ على أمان حسابك، تأكد من إغلاق المتصفح إذا كنت تستخدم جهازًا مشتركًا.
                        </div>
                    </div>

                    <a href="/" style="
                        display:inline-block;
                        text-decoration:none;
                        background:linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                        color:white;
                        padding:14px 28px;
                        border-radius:14px;
                        font-size:15px;
                        font-weight:bold;
                        box-shadow:0 10px 24px rgba(15,23,42,0.22);
                    ">
                        العودة إلى الصفحة الرئيسية
                    </a>
                </div>
            </div>
        </body>
        </html>
    """, "text/html; charset=utf-8")
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