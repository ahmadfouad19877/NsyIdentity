using IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace IdentityServerNSY.account;

public static class AccountEndpoints
{
    public static void MapAccountEndpoints(this WebApplication app)
    {
        // =========================
        // GET: /account/login
        // =========================
        app.MapGet("/account/login", (string? returnUrl, string? ok, string? err) =>
        {
            returnUrl = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;

            var html = BuildLoginHtml(returnUrl, ok, err);
            return Results.Content(html, "text/html; charset=utf-8");
        }).AllowAnonymous();


        // =========================
        // POST: /account/login
        // =========================
        app.MapPost("/account/login", async (
            HttpContext http,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager) =>
        {
            var form = await http.Request.ReadFormAsync();

            var username = form["username"].ToString().Trim();
            var password = form["password"].ToString();
            var returnUrl = form["returnUrl"].ToString();

            returnUrl = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                return Results.Redirect("/account/login?returnUrl=" + WebUtility.UrlEncode(returnUrl) + "&err=" + WebUtility.UrlEncode("missing"));

            var user = await userManager.FindByNameAsync(username);
            if (user is null)
                return Results.Redirect("/account/login?returnUrl=" + WebUtility.UrlEncode(returnUrl) + "&err=" + WebUtility.UrlEncode("invalid"));

            var result = await signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: false);
            if (!result.Succeeded)
                return Results.Redirect("/account/login?returnUrl=" + WebUtility.UrlEncode(returnUrl) + "&err=" + WebUtility.UrlEncode("invalid"));

            await signInManager.SignInAsync(user, isPersistent: false);

            return Results.Redirect(returnUrl);
        }).AllowAnonymous();


        // =========================
        // GET: /cb
        // =========================
        app.MapGet("/cb", async (HttpContext ctx) =>
        {
            var code = ctx.Request.Query["code"].ToString();
            var state = ctx.Request.Query["state"].ToString();
            var error = ctx.Request.Query["error"].ToString();
            var errorDesc = ctx.Request.Query["error_description"].ToString();

            static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

            // ✅ إذا في error: اعرض صفحة Error فخمة + امسح session
            if (!string.IsNullOrWhiteSpace(error))
            {
                ClearAllSessionSafe(ctx);

                var htmlErr = BuildCallbackErrorHtml(
                    safeError: E(error),
                    safeErrorDesc: E(errorDesc),
                    safeState: E(state));

                return Results.Content(htmlErr, "text/html; charset=utf-8");
            }

            // ✅ إذا في code: اعرض Success فخم + امسح session بالكامل
            if (!string.IsNullOrWhiteSpace(code))
            {
                // ✅ امسح كل Session
                ClearAllSessionSafe(ctx);

                // ✅ إذا بدك أيضًا تمسح كوكي تسجيل الدخول (اختياري):
                 await ctx.SignOutAsync(IdentityConstants.ApplicationScheme);

                var htmlOk = BuildCallbackSuccessHtml();
                return Results.Content(htmlOk, "text/html; charset=utf-8");
            }

            // ✅ إذا لا code ولا error: صفحة "No code"
            ClearAllSessionSafe(ctx);

            var htmlNo = BuildCallbackNoCodeHtml(
                safeState: E(state));

            return Results.Content(htmlNo, "text/html; charset=utf-8");
        }).AllowAnonymous();


        // =========================
        // POST: /cb/code (كما عندك - لكن بعد تعديل /cb صار غالبًا غير مستخدم)
        // =========================
        app.MapPost("/cb/code", (HttpContext ctx) =>
        {
            var used = ctx.Session.GetString("cb_code_used");
            if (used == "1") return Results.Unauthorized();

            var code = ctx.Session.GetString("cb_code_value");
            if (string.IsNullOrWhiteSpace(code)) return Results.Unauthorized();

            ctx.Session.SetString("cb_code_used", "1");
            ctx.Session.Remove("cb_code_value");

            return Results.Ok(new { code });
        }).AllowAnonymous();


        // =========================
        // GET: /connect/authorize (كما هو عندك)
        // =========================
        app.MapGet("/connect/authorize", async (HttpContext httpContext) =>
        {
            // ✅ 0) Authenticate explicitly using Cookie scheme (Identity)
            var cookieResult = await httpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

            if (!cookieResult.Succeeded || cookieResult.Principal?.Identity?.IsAuthenticated != true)
            {
                return Results.Challenge(
                    new AuthenticationProperties
                    {
                        RedirectUri = httpContext.Request.PathBase + httpContext.Request.Path + httpContext.Request.QueryString
                    },
                    authenticationSchemes: new[] { IdentityConstants.ApplicationScheme });
            }

            httpContext.User = cookieResult.Principal;

            // 1) OpenIddict request
            var request = httpContext.GetOpenIddictServerRequest();
            if (request is null)
            {
                return ClientErrorPages.Html(
                    title: "Invalid authorization request",
                    message: "OpenIddict request is missing. Please logout and try again.",
                    statusCode: 400);
            }

            // ✅ 1.1) Device params
            var deviceId = request.GetParameter("device_id")?.ToString()
                          ?? httpContext.Request.Query["device_id"].ToString();

            var deviceName = request.GetParameter("device_name")?.ToString()
                            ?? httpContext.Request.Query["device_name"].ToString();

            var platform = request.GetParameter("platform")?.ToString()
                           ?? httpContext.Request.Query["platform"].ToString();

            if (string.IsNullOrWhiteSpace(deviceId) ||
                string.IsNullOrWhiteSpace(deviceName) ||
                string.IsNullOrWhiteSpace(platform))
            {
                return ClientErrorPages.Html(
                    title: "Missing device parameters",
                    message: "device_id, device_name and platform are required on /connect/authorize. Please logout and try again.",
                    statusCode: 400);
            }

            // 2) userId from cookie
            var userId =
                httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ??
                httpContext.User.FindFirstValue(OpenIddictConstants.Claims.Subject);

            // 3) clientId from request
            var clientId = request.ClientId;

            if (string.IsNullOrWhiteSpace(userId))
            {
                return ClientErrorPages.Html(
                    title: "User not identified",
                    message: "UserId is missing from the authentication cookie. Please logout and login again.",
                    statusCode: 403);
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                return ClientErrorPages.Html(
                    title: "Missing client_id",
                    message: "The application did not send client_id. Please logout and try again.",
                    statusCode: 400);
            }

            // ✅ 4) Allow-list
            var db = httpContext.RequestServices.GetRequiredService<ApplicationDb>();

            var isAllowed = await db.AllowedClients.AnyAsync(x =>
                x.UserId == userId &&
                x.ClientId == clientId &&
                x.IsActive);

            if (!isAllowed)
            {
                Console.WriteLine($"❌ Blocked: user {userId} is not allowed for client {clientId}");

                return ClientErrorPages.Html(
                    title: "Client not allowed",
                    message: "This user is not allowed to access this client. Please logout.",
                    clientId: clientId,
                    statusCode: 403);
            }

            // 5) ClaimsIdentity
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            identity.AddClaim(OpenIddictConstants.Claims.Subject, userId);

            var name = httpContext.User.Identity?.Name;
            if (!string.IsNullOrWhiteSpace(name))
                identity.AddClaim(OpenIddictConstants.Claims.Name, name);

            identity.AddClaim("azp", clientId);

            foreach (var role in httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value))
                identity.AddClaim(OpenIddictConstants.Claims.Role, role);

            // ✅ internal device claims
            identity.AddClaim("device_id", deviceId);
            identity.AddClaim("device_name", deviceName);
            identity.AddClaim("platform", platform);

            var principal = new ClaimsPrincipal(identity);

            principal.SetScopes(request.GetScopes());

            // ✅ حل LastOrDefaultAsync: لازم OrderBy محدد
            var allow = await db.AllowedAudiences
                .AsNoTracking()
                .Where(x => x.IsActive && x.ClientId == clientId)
                .OrderByDescending(x => x.CreatedAtUtc)
                .ToListAsync();

            // ✅ Audiences
            var audiences = new List<string>();
            //audiences.Add("ItemPrice");
            if (allow.Count > 0)
              audiences.AddRange(
                allow
                  .Where(x => !string.IsNullOrWhiteSpace(x.Audience))
                  .Select(x => x.Audience)
              );
            // remove duplicates
            //audiences = audiences.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            principal.SetAudiences(audiences);

            principal.SetDestinations(claim => claim.Type switch
            {
                OpenIddictConstants.Claims.Subject => new[]
                {
                    OpenIddictConstants.Destinations.AccessToken,
                    OpenIddictConstants.Destinations.IdentityToken
                },

                OpenIddictConstants.Claims.Name => new[]
                {
                    OpenIddictConstants.Destinations.AccessToken,
                    OpenIddictConstants.Destinations.IdentityToken
                },

                OpenIddictConstants.Claims.Role => new[]
                {
                    OpenIddictConstants.Destinations.AccessToken
                },

                "azp" => new[]
                {
                    OpenIddictConstants.Destinations.AccessToken
                },

                // ✅ do NOT leak device info
                "device_id" => Array.Empty<string>(),
                "device_name" => Array.Empty<string>(),
                "platform" => Array.Empty<string>(),

                _ => new[]
                {
                    OpenIddictConstants.Destinations.AccessToken
                }
            });

            return Results.SignIn(
                principal,
                properties: null,
                authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        }).AllowAnonymous();


        // =========================
        // HTML Builders (Same Style)
        // =========================

        static string BuildSecureBarHtml()
        {
            return """
                   <div class="secureBar">
                     <div class="lock">🔒</div>
                     <div class="secureText">
                       <div class="secureTitle">Secure Connection</div>
                       <div class="secureSub">SSL / TLS Enabled</div>
                     </div>
                     <div class="pill">SSL</div>
                   </div>
                   """;
        }

        static string Enc(string? s) => WebUtility.HtmlEncode(s ?? "");

        static void ClearAllSessionSafe(HttpContext ctx)
        {
            try
            {
                ctx.Session.Clear();

                // إزالة مفاتيح معروفة (اختياري)
                ctx.Session.Remove("cb_code_used");
                ctx.Session.Remove("cb_code_value");
                ctx.Session.Remove("pkce_state");
                ctx.Session.Remove("pkce_verifier");
            }
            catch
            {
                // لا تفشل الطلب بسبب session
            }
        }

        static string BuildLoginHtml(string returnUrl, string? ok, string? err)
        {
            var safeReturn = Enc(returnUrl);

            var okHtml = ok == "created"
                ? """
                  <div class="alert ok">
                    <div class="ico">✅</div>
                    <div class="txt">Account created successfully. Please sign in.</div>
                  </div>
                  """
                : "";

            var errMsg = err switch
            {
                "missing" => "Please enter username and password.",
                "invalid" => "Invalid username or password.",
                _ => ""
            };

            var errHtml = string.IsNullOrWhiteSpace(errMsg)
                ? ""
                : $"""
                   <div class="alert err">
                     <div class="ico">⚠️</div>
                     <div class="txt">{Enc(errMsg)}</div>
                   </div>
                   """;

            return $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
  <meta charset=""utf-8"" />
  <meta name=""viewport"" content=""width=device-width, initial-scale=1"" />
  <title>Sign In</title>

  <style>
    :root {{
      --bg0:#050507;
      --bg1:#0b0b10;
      --line: rgba(255,255,255,0.10);
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.62);
      --gold:#d8c38a;
      --shadow: 0 22px 60px rgba(0,0,0,0.65);
      --radius: 26px;
      --field: rgba(255,255,255,0.06);
      --field2: rgba(255,255,255,0.08);
    }}

    * {{ box-sizing:border-box; }}
    body {{
      margin:0;
      min-height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      background:
        radial-gradient(900px 500px at 25% 15%, rgba(216,195,138,0.10), transparent 55%),
        radial-gradient(700px 500px at 80% 35%, rgba(255,255,255,0.06), transparent 60%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, ""Segoe UI"", Roboto, Arial;
      padding: 28px 18px;
    }}

    .phoneFrame {{ width: 100%; max-width: 420px; }}

    .sheet {{
      background: linear-gradient(180deg, rgba(20,20,28,0.88), rgba(14,14,18,0.88));
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
      padding: 16px 18px 18px;
    }}

    .secureBar {{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.10);
      background: rgba(255,255,255,0.04);
      margin-bottom: 14px;
    }}
    .lock {{
      width: 34px; height: 34px;
      border-radius: 12px;
      display:flex; align-items:center; justify-content:center;
      background: rgba(216,195,138,0.12);
      border: 1px solid rgba(216,195,138,0.25);
      flex: 0 0 34px;
      font-size: 16px;
    }}
    .secureText {{ flex:1; }}
    .secureTitle {{ font-size: 13px; font-weight: 800; color: rgba(255,255,255,0.90); }}
    .secureSub {{ font-size: 11px; color: rgba(255,255,255,0.55); margin-top: 2px; }}
    .pill {{
      font-size: 11px;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.12);
      color: rgba(255,255,255,0.75);
      white-space: nowrap;
    }}

    .titleRow {{
      display:flex;
      align-items:baseline;
      gap: 8px;
      margin-top: 6px;
    }}
    .title {{
      font-family: Georgia, ""Times New Roman"", serif;
      font-size: 34px;
      margin:0;
      color: var(--gold);
      font-style: italic;
      letter-spacing: 0.2px;
    }}
    .title2 {{
      font-family: Georgia, ""Times New Roman"", serif;
      font-size: 34px;
      margin:0;
      color: rgba(255,255,255,0.86);
    }}
    .desc {{
      margin: 10px 0 18px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }}

    .alert {{
      display:flex;
      gap:10px;
      align-items:flex-start;
      padding: 12px 12px;
      border-radius: 16px;
      margin: 10px 0 14px;
      border:1px solid;
      background: rgba(255,255,255,0.04);
    }}
    .alert .ico {{
      width: 28px; height: 28px;
      border-radius: 10px;
      display:flex; align-items:center; justify-content:center;
      background: rgba(255,255,255,0.06);
      flex: 0 0 28px;
    }}
    .alert .txt {{
      font-size: 13px;
      color: rgba(255,255,255,0.9);
      line-height: 1.35;
      padding-top: 3px;
    }}
    .alert.err {{ border-color: rgba(239,68,68,0.35); background: rgba(239,68,68,0.08); }}
    .alert.ok  {{ border-color: rgba(16,185,129,0.35); background: rgba(16,185,129,0.08); }}

    label {{
      display:block;
      margin: 12px 0 8px;
      color: rgba(255,255,255,0.80);
      font-size: 14px;
      letter-spacing: 0.2px;
    }}

    .field {{
      width:100%;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.08));
      padding: 14px 14px;
      color: rgba(255,255,255,0.92);
      outline: none;
      font-size: 15px;
    }}
    .field::placeholder {{ color: rgba(255,255,255,0.35); }}
    .field:focus {{
      border-color: rgba(216,195,138,0.45);
      box-shadow: 0 0 0 4px rgba(216,195,138,0.12);
    }}

    .pwdWrap {{ position: relative; }}
    .eye {{
      position:absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      border:none;
      background: transparent;
      color: rgba(255,255,255,0.65);
      cursor:pointer;
      padding: 8px;
      border-radius: 12px;
    }}
    .eye:hover {{ background: rgba(255,255,255,0.06); }}

    .actionBar {{
      margin-top: 18px;
      display:flex;
      gap: 12px;
      align-items:center;
      justify-content:space-between;
      padding: 12px 12px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.10);
      background: rgba(255,255,255,0.04);
    }}
    .btnGold {{
      flex:1;
      border:none;
      cursor:pointer;
      border-radius: 999px;
      padding: 16px 18px;
      background: linear-gradient(180deg, #f1e5be, var(--gold));
      color: #1b1407;
      font-weight: 900;
      letter-spacing: 1px;
      font-size: 16px;
      text-transform: uppercase;
    }}
    .btnGold:hover {{ filter: brightness(1.03); }}

    .go {{
      width: 54px; height: 54px;
      border-radius: 999px;
      background: rgba(255,255,255,0.92);
      color: #0b0b10;
      display:flex; align-items:center; justify-content:center;
      font-size: 22px;
      border: none;
      cursor:pointer;
    }}
    .go:hover {{ filter: brightness(0.97); }}
  </style>
</head>

<body>
  <div class=""phoneFrame"">
    <div class=""sheet"">
      {BuildSecureBarHtml()}

      <div class=""titleRow"">
        <h1 class=""title"">Secure</h1>
        <h1 class=""title2"">Login</h1>
      </div>

      <div class=""desc"">
        Please verify your identity to continue.
      </div>

      {okHtml}
      {errHtml}

      <form id=""loginForm"" method=""post"" action=""/account/login"" autocomplete=""off"">
        <input type=""hidden"" name=""returnUrl"" value=""{safeReturn}"" />

        <label>Username</label>
        <input class=""field"" id=""username"" name=""username"" placeholder=""username"" required />

        <label>Password</label>
        <div class=""pwdWrap"">
          <input class=""field"" id=""pwd"" type=""password"" name=""password"" placeholder=""••••••••"" required />
          <button class=""eye"" type=""button"" onclick=""togglePwd('pwd')"" aria-label=""Show password"">👁</button>
        </div>

        <div class=""actionBar"">
          <button class=""btnGold"" type=""submit"">SIGN IN</button>
          <button class=""go"" type=""submit"" aria-label=""Submit"">›</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    function togglePwd(id) {{
      var input = document.getElementById(id);
      if (!input) return;
      input.type = (input.type === 'password') ? 'text' : 'password';
    }}

    (function() {{
      var u = document.getElementById('username');
      if (!u) return;
      u.addEventListener('input', function() {{
        var v = (u.value || '').toLowerCase();
        v = v.replace(/\\s+/g, '');
        v = v.replace(/[^a-z0-9._-]/g, '');
        u.value = v;
      }});
    }})();
  </script>
</body>
</html>";
        }

        // ✅ Success page
        static string BuildCallbackSuccessHtml()
        {
            return $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
  <meta charset=""utf-8"" />
  <meta name=""viewport"" content=""width=device-width, initial-scale=1"" />
  <title>Success</title>

  <style>
    :root {{
      --bg0:#050507;
      --bg1:#0b0b10;
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.62);
      --gold:#d8c38a;
      --shadow: 0 22px 60px rgba(0,0,0,0.65);
      --radius: 26px;
      --line: rgba(255,255,255,0.10);
    }}
    * {{ box-sizing:border-box; }}
    body {{
      margin:0;
      min-height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      background:
        radial-gradient(900px 500px at 25% 15%, rgba(216,195,138,0.10), transparent 55%),
        radial-gradient(700px 500px at 80% 35%, rgba(255,255,255,0.06), transparent 60%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, ""Segoe UI"", Roboto, Arial;
      padding: 28px 18px;
    }}
    .wrap {{ width:100%; max-width:520px; }}
    .sheet {{
      background: linear-gradient(180deg, rgba(20,20,28,0.88), rgba(14,14,18,0.88));
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
      padding: 18px;
    }}
    .top {{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.10);
      background: rgba(255,255,255,0.04);
      margin-bottom: 14px;
    }}
    .lock {{
      width: 34px; height: 34px;
      border-radius: 12px;
      display:flex; align-items:center; justify-content:center;
      background: rgba(216,195,138,0.12);
      border: 1px solid rgba(216,195,138,0.25);
      flex: 0 0 34px;
      font-size: 16px;
    }}
    .pill {{
      font-size: 11px;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(16,185,129,0.12);
      border: 1px solid rgba(16,185,129,0.25);
      color: rgba(255,255,255,0.80);
      white-space: nowrap;
      display:inline-block;
    }}
    .titleRow {{
      display:flex;
      align-items:baseline;
      gap: 8px;
      margin-top: 6px;
    }}
    .title {{
      font-family: Georgia, ""Times New Roman"", serif;
      font-size: 34px;
      margin:0;
      color: var(--gold);
      font-style: italic;
    }}
    .title2 {{
      font-family: Georgia, ""Times New Roman"", serif;
      font-size: 34px;
      margin:0;
      color: rgba(255,255,255,0.86);
    }}
    .desc {{
      margin: 12px 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.55;
    }}
    .ok {{
      margin-top: 16px;
      padding: 14px 14px;
      border-radius: 18px;
      border: 1px solid rgba(16,185,129,0.35);
      background: rgba(16,185,129,0.10);
      display:flex;
      gap: 10px;
      align-items:flex-start;
    }}
    .ico {{
      width: 34px; height: 34px;
      border-radius: 12px;
      display:flex; align-items:center; justify-content:center;
      background: rgba(16,185,129,0.14);
      border: 1px solid rgba(16,185,129,0.25);
      flex: 0 0 34px;
      font-size: 16px;
    }}
    .txt {{
      font-size: 13px;
      line-height: 1.45;
      color: rgba(255,255,255,0.90);
    }}
    .hint {{
      margin-top: 10px;
      color: rgba(255,255,255,0.55);
      font-size: 12px;
    }}
    .btn {{
      margin-top: 16px;
      width: 100%;
      border: none;
      cursor: pointer;
      border-radius: 18px;
      padding: 14px 14px;
      background: linear-gradient(180deg, #f1e5be, var(--gold));
      color: #1b1407;
      font-weight: 900;
      letter-spacing: 0.8px;
      text-transform: uppercase;
      font-size: 13px;
    }}
    .btn:hover {{ filter: brightness(1.03); }}
  </style>
</head>

<body>
  <div class=""wrap"">
    <div class=""sheet"">
      <div class=""top"">
        <div style=""display:flex;gap:10px;align-items:center"">
          <div class=""lock"">🔒</div>
          <div>
            <div style=""font-size:13px;font-weight:800;color:rgba(255,255,255,0.9)"">Secure Connection</div>
            <div style=""font-size:11px;color:rgba(255,255,255,0.55);margin-top:2px"">SSL / TLS Enabled</div>
          </div>
        </div>
        <div class=""pill"">SUCCESS</div>
      </div>

      <div class=""titleRow"">
        <h1 class=""title"">Login</h1>
        <h1 class=""title2"">Success</h1>
      </div>

      <div class=""desc"">
        You can safely close this page and return to the application.
      </div>

      <div class=""ok"">
        <div class=""ico"">✅</div>
        <div class=""txt"">
          Authentication completed successfully.<br/>
          For security, all temporary session data was cleared.
          <div class=""hint"">If you opened this page inside a WebView, you can now close it.</div>
        </div>
      </div>

      <button class=""btn"" type=""button"" onclick=""window.close(); setTimeout(()=>location.replace('/'), 200);"">
        Close
      </button>
    </div>
  </div>
</body>
</html>";
        }

        // ✅ No code page
        static string BuildCallbackNoCodeHtml(string safeState)
        {
            return $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
  <meta charset=""utf-8"" />
  <meta name=""viewport"" content=""width=device-width, initial-scale=1"" />
  <title>Callback</title>

  <style>
    :root {{
      --bg0:#050507;
      --bg1:#0b0b10;
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.62);
      --gold:#d8c38a;
      --shadow: 0 22px 60px rgba(0,0,0,0.65);
      --radius: 26px;
    }}

    * {{ box-sizing:border-box; }}
    body {{
      margin:0;
      min-height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      background:
        radial-gradient(900px 500px at 25% 15%, rgba(216,195,138,0.10), transparent 55%),
        radial-gradient(700px 500px at 80% 35%, rgba(255,255,255,0.06), transparent 60%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, ""Segoe UI"", Roboto, Arial;
      padding: 28px 18px;
    }}

    .wrap {{ width:100%; max-width:520px; }}
    .sheet {{
      background: linear-gradient(180deg, rgba(20,20,28,0.88), rgba(14,14,18,0.88));
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
      padding: 18px;
    }}

    .titleRow {{
      display:flex;
      align-items:baseline;
      gap: 8px;
      margin-top: 6px;
    }}
    .title {{
      font-family: Georgia, ""Times New Roman"", serif;
      font-size: 34px;
      margin:0;
      color: var(--gold);
      font-style: italic;
    }}
    .title2 {{
      font-family: Georgia, ""Times New Roman"", serif;
      font-size: 34px;
      margin:0;
      color: rgba(255,255,255,0.86);
    }}

    .desc {{
      margin: 12px 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.55;
    }}

    .box {{
      margin-top: 16px;
      padding: 14px 14px;
      border-radius: 18px;
      border: 1px solid rgba(245,158,11,0.30);
      background: rgba(245,158,11,0.10);
      font-size: 13px;
      line-height: 1.45;
    }}

    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, ""Liberation Mono"", ""Courier New"", monospace;
      word-break: break-all;
    }}
  </style>
</head>

<body>
  <div class=""wrap"">
    <div class=""sheet"">
      <div class=""titleRow"">
        <h1 class=""title"">Callback</h1>
        <h1 class=""title2"">Missing</h1>
      </div>

      <div class=""desc"">
        The callback was reached but no authorization <b>code</b> was found.
      </div>

      <div class=""box"">
        <div><b>State</b>: <code>{safeState}</code></div>
        <div style=""margin-top:8px;color:rgba(255,255,255,0.70)"">Please try again from the app.</div>
      </div>
    </div>
  </div>
</body>
</html>";
        }

        // ✅ Error page
        static string BuildCallbackErrorHtml(string safeError, string safeErrorDesc, string safeState)
        {
            return $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
  <meta charset=""utf-8"" />
  <meta name=""viewport"" content=""width=device-width, initial-scale=1"" />
  <title>Callback Error</title>

  <style>
    :root {{
      --bg0:#050507;
      --bg1:#0b0b10;
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.62);
      --gold:#d8c38a;
      --shadow: 0 22px 60px rgba(0,0,0,0.65);
      --radius: 26px;
    }}

    * {{ box-sizing:border-box; }}
    body {{
      margin:0;
      min-height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      background:
        radial-gradient(900px 500px at 25% 15%, rgba(216,195,138,0.10), transparent 55%),
        radial-gradient(700px 500px at 80% 35%, rgba(255,255,255,0.06), transparent 60%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, ""Segoe UI"", Roboto, Arial;
      padding: 28px 18px;
    }}

    .wrap {{ width:100%; max-width:520px; }}
    .sheet {{
      background: linear-gradient(180deg, rgba(20,20,28,0.88), rgba(14,14,18,0.88));
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
      padding: 18px;
    }}

    .titleRow {{
      display:flex;
      align-items:baseline;
      gap: 8px;
      margin-top: 6px;
    }}
    .title {{
      font-family: Georgia, ""Times New Roman"", serif;
      font-size: 34px;
      margin:0;
      color: var(--gold);
      font-style: italic;
    }}
    .title2 {{
      font-family: Georgia, ""Times New Roman"", serif;
      font-size: 34px;
      margin:0;
      color: rgba(255,255,255,0.86);
    }}

    .desc {{
      margin: 12px 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.55;
    }}

    .box {{
      margin-top: 16px;
      padding: 14px 14px;
      border-radius: 18px;
      border: 1px solid rgba(239,68,68,0.35);
      background: rgba(239,68,68,0.10);
      font-size: 13px;
      line-height: 1.45;
    }}

    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, ""Liberation Mono"", ""Courier New"", monospace;
      word-break: break-all;
    }}
  </style>
</head>

<body>
  <div class=""wrap"">
    <div class=""sheet"">
      <div class=""titleRow"">
        <h1 class=""title"">Callback</h1>
        <h1 class=""title2"">Error</h1>
      </div>

      <div class=""desc"">
        Authentication failed.
      </div>

      <div class=""box"">
        <div><b>error</b>: <code>{safeError}</code></div>
        {(string.IsNullOrWhiteSpace(safeErrorDesc) ? "" : $@"<div style=""margin-top:8px""><b>error_description</b>: <code>{safeErrorDesc}</code></div>")}
        {(string.IsNullOrWhiteSpace(safeState) ? "" : $@"<div style=""margin-top:8px""><b>state</b>: <code>{safeState}</code></div>")}
      </div>
    </div>
  </div>
</body>
</html>";
        }
    }
}
