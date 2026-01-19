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
        app.MapGet("/cb", (HttpContext ctx) =>
        {
            var qs = ctx.Request.QueryString.Value ?? "";
            var safeQs = WebUtility.HtmlEncode(qs);

            var code = ctx.Request.Query["code"].ToString();
            var state = ctx.Request.Query["state"].ToString();
            var error = ctx.Request.Query["error"].ToString();
            var errorDesc = ctx.Request.Query["error_description"].ToString();

            static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

            var safeCode = E(code);
            var safeState = E(state);
            var safeError = E(error);
            var safeErrorDesc = E(errorDesc);

            var hasCode = !string.IsNullOrWhiteSpace(code);
            var hasError = !string.IsNullOrWhiteSpace(error);

            // raw values into JS safely
            var jsCode = System.Text.Json.JsonSerializer.Serialize(code ?? "");
            var jsState = System.Text.Json.JsonSerializer.Serialize(state ?? "");

            var html = BuildCallbackHtml(
                hasError: hasError,
                hasCode: hasCode,
                safeCode: safeCode,
                safeState: safeState,
                safeError: safeError,
                safeErrorDesc: safeErrorDesc,
                safeQs: safeQs,
                jsCode: jsCode,
                jsState: jsState
            );

            return Results.Content(html, "text/html; charset=utf-8");
        }).AllowAnonymous();


        // =========================
        // POST: /cb/code (كما عندك)
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
                x.IsEnabled);

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
            var allow=await db.AllowedClients.OrderBy(x=>x.CreatedAt)
              .LastOrDefaultAsync(x=>x.IsEnabled&&x.ClientId==clientId&&x.UserId == userId);

            //هاي لازمها حللللللللللل
            //principal.SetAudiences("Currency");
            var audiences = new List<string>();
            if (allow?.AllowedAudiences?.Count > 0)
            {
              audiences.AddRange(allow.AllowedAudiences);
            }
            
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
      background: linear-gradient(180deg, var(--field), var(--field2));
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

    .below {{
      text-align:center;
      margin-top: 14px;
      color: rgba(255,255,255,0.65);
      font-size: 13px;
    }}
    .below a {{
      color: var(--gold);
      font-weight: 900;
      text-decoration:none;
      letter-spacing: 0.4px;
    }}
    .below a:hover {{ text-decoration: underline; }}
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

    // OPTIONAL: sanitize username same idea (no arabic)
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

        static string BuildCallbackHtml(
            bool hasError,
            bool hasCode,
            string safeCode,
            string safeState,
            string safeError,
            string safeErrorDesc,
            string safeQs,
            string jsCode,
            string jsState)
        {
            var topTitle1 = hasError ? "Callback" : "Callback";
            var topTitle2 = hasError ? "Error" : "Received";

            var pills = hasError
                ? @"<span class=""pill err"">ERROR</span>"
                : (hasCode ? @"<span class=""pill ok"">CODE FOUND</span>" : @"<span class=""pill"">NO CODE</span>");

            var statePill = string.IsNullOrWhiteSpace(safeState) ? "" : @"&nbsp;&nbsp;<span class=""pill"">STATE PRESENT</span>";

            var bodyBlock = hasError
                ? $@"
                    <div class=""alert err"">
                      <div class=""ico"">❌</div>
                      <div class=""txt"">
                        <div style=""font-weight:900;margin-bottom:6px"">Authentication failed</div>
                        <div><b>error</b>: <code>{safeError}</code></div>
                        {(string.IsNullOrWhiteSpace(safeErrorDesc) ? "" : $@"<div style=""margin-top:6px""><b>error_description</b>: <code>{safeErrorDesc}</code></div>")}
                      </div>
                    </div>
                  "
                : $@"
                    <div class=""desc"" style=""margin-top:6px"">
                      One click: copy the code (Safari-stable) then POST <b>/account/logoutcode</b>.
                    </div>

                    <div class=""row"">
                      <div id=""codeBox"" class=""code-box"" oncopy=""return false"" oncut=""return false"" oncontextmenu=""return false"">
                        {(hasCode ? safeCode : "<span style='color:rgba(255,255,255,0.45)'>No code parameter found.</span>")}
                      </div>

                      <button id=""copyBtn"" class=""btnGoldSmall"" {(hasCode ? "" : "disabled")}>
                        Copy Code & Logout
                      </button>
                    </div>

                    {(string.IsNullOrWhiteSpace(safeState) ? "" : $@"
                      <div style=""margin-top:14px;color:rgba(255,255,255,0.62);font-size:13px""><b>State</b></div>
                      <div class=""code-box"" style=""margin-top:8px"">{safeState}</div>
                    ")}
                  ";

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

    .phoneFrame {{ width: 100%; max-width: 520px; }}

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
      display:inline-block;
    }}
    .pill.ok {{ background: rgba(16,185,129,0.12); border-color: rgba(16,185,129,0.25); }}
    .pill.err {{ background: rgba(239,68,68,0.12); border-color: rgba(239,68,68,0.25); }}

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
      width: 100%;
    }}
    .alert.err {{ border-color: rgba(239,68,68,0.35); background: rgba(239,68,68,0.08); }}

    .row {{
      display:flex;
      gap: 12px;
      align-items: stretch;
      margin-top: 12px;
    }}

    .code-box {{
      flex: 1;
      border-radius: 18px;
      border: 1px dashed rgba(216,195,138,0.35);
      background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.06));
      padding: 14px 14px;
      color: rgba(255,255,255,0.92);
      outline: none;
      font-size: 13px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, ""Liberation Mono"", ""Courier New"", monospace;
      word-break: break-all;
      user-select:none;
      -webkit-user-select:none;
      -webkit-touch-callout:none;
      display:flex;
      align-items:center;
      min-height: 52px;
    }}

    .btnGoldSmall {{
      width: 210px;
      border:none;
      cursor:pointer;
      border-radius: 18px;
      padding: 14px 14px;
      background: linear-gradient(180deg, #f1e5be, var(--gold));
      color: #1b1407;
      font-weight: 900;
      letter-spacing: 0.8px;
      font-size: 13px;
      text-transform: uppercase;
    }}
    .btnGoldSmall:disabled {{
      opacity: .55;
      cursor: not-allowed;
      filter: grayscale(0.2);
    }}

    details {{ margin-top: 14px; }}
    summary {{ cursor:pointer; color: rgba(255,255,255,0.55); font-size: 13px; }}

    .qs {{
      margin-top: 10px;
      background: rgba(0,0,0,0.35);
      border: 1px solid rgba(255,255,255,0.10);
      color: rgba(255,255,255,0.75);
      border-radius: 18px;
      padding: 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, ""Liberation Mono"", ""Courier New"", monospace;
      font-size: 12px;
      word-break: break-all;
    }}

    .toast {{
      position: fixed;
      left: 50%;
      bottom: 22px;
      transform: translateX(-50%);
      background: rgba(17,24,39,0.92);
      color: #fff;
      padding: 10px 14px;
      border-radius: 999px;
      font-size: 13px;
      opacity: 0;
      pointer-events: none;
      transition: opacity .2s ease;
    }}
    .toast.show {{ opacity: 1; }}
  </style>
</head>

<body>
  <div class=""phoneFrame"">
    <div class=""sheet"">
      {BuildSecureBarHtml()}

      <div class=""titleRow"">
        <h1 class=""title"">{topTitle1}</h1>
        <h1 class=""title2"">{topTitle2}</h1>
      </div>

      <div class=""desc"">
        {(hasError ? "The authorization server returned an error." : "Use the button to copy the code and logout immediately.")}
      </div>

      <div style=""display:flex;justify-content:center;margin-bottom:10px"">
        {pills}{statePill}
      </div>

      {bodyBlock}

      <details>
        <summary>Show full query string</summary>
        <div class=""qs"">{safeQs}</div>
      </details>
    </div>
  </div>

  <div id=""toast"" class=""toast"">Copied ✅</div>

  <script>
    (function () {{
      const CODE = {jsCode};
      const STATE = {jsState};
      const toast = document.getElementById('toast');
      const copyBtn = document.getElementById('copyBtn');

      function showToast(msg) {{
        if (!toast) return;
        toast.textContent = msg;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 1700);
      }}

      // ✅ Safari-stable copy
      function copyStable(text) {{
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        ta.style.top = '0';
        document.body.appendChild(ta);

        ta.focus();
        ta.select();
        ta.setSelectionRange(0, text.length);

        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        return ok;
      }}

      async function logoutCode() {{
        const r = await fetch('/account/logoutcode', {{
          method: 'POST',
          credentials: 'include',
          keepalive: true,
          headers: {{ 'Content-Type': 'application/json' }},
          body: '{{}}'
        }});

        if (!r.ok) throw new Error('logout_failed_' + r.status);
      }}

      if (copyBtn && !copyBtn.disabled) {{
        copyBtn.addEventListener('click', async () => {{
          copyBtn.disabled = true;
          copyBtn.textContent = 'WORKING...';

          try {{
            const ok = copyStable(CODE);
            if (!ok) throw new Error('copy_failed');

            showToast('Copied ✅ Logging out...');

            await logoutCode();

            showToast('Logged out 🔐');

            setTimeout(() => window.location.replace('/logout-success'), 450);
          }} catch (e) {{
            showToast('Failed ❌');
            copyBtn.disabled = false;
            copyBtn.textContent = 'COPY CODE & LOGOUT';
          }}
        }});
      }}
    }})();
  </script>
</body>
</html>";
        }
    }
}




/*
 * app.MapGet("/connect/authorize", async (HttpContext httpContext) =>
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

       // ✅ 0.1) Make sure the cookie principal is used for reading claims (userId/roles/name)
       httpContext.User = cookieResult.Principal;

       // 1) OpenIddict request
       var request = httpContext.GetOpenIddictServerRequest()
                    ?? throw new InvalidOperationException("OpenIddict request is missing.");

       // ✅ 1.1) Device params from query (Redirect)
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
           return Results.BadRequest(new
           {
               error = "invalid_request",
               error_description = "device_id, device_name and platform are required on /connect/authorize"
           });
       }

       // 2) userId from cookie
       var userId =
           httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ??
           httpContext.User.FindFirstValue(OpenIddictConstants.Claims.Subject);

       // 3) clientId from request
       var clientId = request.ClientId;

       if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(clientId))
           return Results.Forbid();

       // ✅ 4) Allow-list
       var db = httpContext.RequestServices.GetRequiredService<ApplicationDb>();

       var isAllowed = await db.AllowedClients.AnyAsync(x =>
           x.UserId == userId &&
           x.ClientId == clientId &&
           x.IsEnabled);

       if (!isAllowed)
       {
           Console.WriteLine($"❌ Blocked: user {userId} is not allowed for client {clientId}");
           return Results.Forbid();
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

       // ✅ internal device claims (keep them in code only)
       identity.AddClaim("device_id", deviceId);
       identity.AddClaim("device_name", deviceName);
       identity.AddClaim("platform", platform);

       var principal = new ClaimsPrincipal(identity);

       principal.SetScopes(request.GetScopes());

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

           // ✅ do NOT leak device info in access/id tokens
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
 */




