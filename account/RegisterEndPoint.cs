using System.Net;
using System.Text.RegularExpressions;
using IdentityServer.Interface;
using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityServerNSY.account;

public static class RegisterEndPoint
{
    public static void MapRegisterEndpoints(this WebApplication app)
    {
        app.MapGet("/account/register", (string? returnUrl, string? ok) =>
        {
            returnUrl = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;

            return Results.Content(
                BuildRegisterHtml(
                    returnUrl: returnUrl,
                    ok: ok,
                    errCode: null,
                    errMessage: null,
                    values: new RegisterValues()),
                "text/html; charset=utf-8");
        }).AllowAnonymous();


        app.MapPost("/account/register", async (
            HttpContext http,
            UserManager<ApplicationUser> userManager,
            IUserAllowedClientRep _allowedClient
        ) =>
        {
            var form = await http.Request.ReadFormAsync();

            var values = new RegisterValues
            {
                FName = form["fname"].ToString().Trim(),
                LName = form["lname"].ToString().Trim(),
                Identity = form["identity"].ToString().Trim(),
                Gender = form["gender"].ToString().Trim(),
                Birthday = form["birthday"].ToString().Trim(),
                Phone = "",
                Email = form["email"].ToString().Trim(),
                Username = form["username"].ToString().Trim(),
                ReturnUrl = form["returnUrl"].ToString().Trim()
            };

            var password = form["password"].ToString();
            var confirm = form["confirm"].ToString();

            values.ReturnUrl = string.IsNullOrWhiteSpace(values.ReturnUrl) ? "/" : values.ReturnUrl;

            // ✅ Build phone (cc + local)
            var phoneDirect = form["phone"].ToString().Trim();
            var cc = form["cc"].ToString().Trim();
            var local = form["phone_local"].ToString().Trim();

            var finalPhone = !string.IsNullOrWhiteSpace(phoneDirect)
                ? phoneDirect
                : (cc + local);

            values.Phone = NormalizeInternationalPhone(finalPhone);

            // ✅ Normalize username (lower+remove spaces)
            values.Username = NormalizeUsername(values.Username);

            // ✅ Normalize identity: digits only
            values.Identity = NormalizeDigitsOnly(values.Identity);

            // ✅ Email trim
            values.Email = values.Email.Trim();

            // ✅ required
            if (string.IsNullOrWhiteSpace(values.FName) ||
                string.IsNullOrWhiteSpace(values.LName) ||
                string.IsNullOrWhiteSpace(values.Identity) ||
                string.IsNullOrWhiteSpace(values.Gender) ||
                string.IsNullOrWhiteSpace(values.Birthday) ||
                string.IsNullOrWhiteSpace(values.Phone) ||
                string.IsNullOrWhiteSpace(values.Email) ||
                string.IsNullOrWhiteSpace(values.Username) ||
                string.IsNullOrWhiteSpace(password) ||
                string.IsNullOrWhiteSpace(confirm))
            {
                return Results.Content(
                    BuildRegisterHtml(values.ReturnUrl, null, "missing", "Please fill in all required fields.", values),
                    "text/html; charset=utf-8");
            }

            // ✅ Username backend validation (no Arabic)
            if (!IsValidUsername(values.Username))
            {
                return Results.Content(
                    BuildRegisterHtml(
                        values.ReturnUrl,
                        null,
                        "username_invalid",
                        "Username must be English letters/numbers only (a-z, 0-9) and can include . _ - (3 to 32 chars).",
                        values),
                    "text/html; charset=utf-8");
            }

            // ✅ Identity backend validation: digits only
            if (!IsDigitsOnly(values.Identity))
            {
                return Results.Content(
                    BuildRegisterHtml(
                        values.ReturnUrl,
                        null,
                        "identity_invalid",
                        "Identity must contain digits only.",
                        values),
                    "text/html; charset=utf-8");
            }

            // ✅ Email backend validation: ASCII only + basic format
            if (!IsAsciiOnly(values.Email))
            {
                return Results.Content(
                    BuildRegisterHtml(
                        values.ReturnUrl,
                        null,
                        "email_invalid",
                        "Email must be English/ASCII only (no Arabic characters).",
                        values),
                    "text/html; charset=utf-8");
            }

            if (!IsValidEmailBasic(values.Email))
            {
                return Results.Content(
                    BuildRegisterHtml(
                        values.ReturnUrl,
                        null,
                        "email_invalid_format",
                        "Please enter a valid email address.",
                        values),
                    "text/html; charset=utf-8");
            }

            // ✅ Phone validation (E.164)
            if (!IsValidInternationalPhone(values.Phone))
            {
                return Results.Content(
                    BuildRegisterHtml(
                        values.ReturnUrl,
                        null,
                        "phone_invalid",
                        "Invalid phone number. Use international format like +905076759999 (starts with + and digits only).",
                        values),
                    "text/html; charset=utf-8");
            }

            if (!string.Equals(password, confirm, StringComparison.Ordinal))
            {
                return Results.Content(
                    BuildRegisterHtml(values.ReturnUrl, null, "pwd_mismatch", "Password and Confirm Password do not match.", values),
                    "text/html; charset=utf-8");
            }

            if (!int.TryParse(values.Gender, out var genderInt) || genderInt < 0 || genderInt > 1)
            {
                return Results.Content(
                    BuildRegisterHtml(values.ReturnUrl, null, "gender_invalid", "Please select a valid gender.", values),
                    "text/html; charset=utf-8");
            }

            // ✅ Unique checks
            if (await userManager.FindByNameAsync(values.Username) is not null)
            {
                return Results.Content(
                    BuildRegisterHtml(values.ReturnUrl, null, "username_exists", "This username is already taken.", values),
                    "text/html; charset=utf-8");
            }

            if (await userManager.FindByEmailAsync(values.Email) is not null)
            {
                return Results.Content(
                    BuildRegisterHtml(values.ReturnUrl, null, "email_exists", "This email is already registered.", values),
                    "text/html; charset=utf-8");
            }

            if (await userManager.Users.AnyAsync(u => u.PhoneNumber == values.Phone))
            {
                return Results.Content(
                    BuildRegisterHtml(values.ReturnUrl, null, "phone_exists", "This phone number is already registered.", values),
                    "text/html; charset=utf-8");
            }

            if (await userManager.Users.AnyAsync(u => u.Identity == values.Identity))
            {
                return Results.Content(
                    BuildRegisterHtml(values.ReturnUrl, null, "identity_exists", "This identity number is already registered.", values),
                    "text/html; charset=utf-8");
            }

            var user = new ApplicationUser
            {
                UserName = values.Username,
                Email = values.Email,
                PhoneNumber = values.Phone,
                FName = values.FName,
                LName = values.LName,
                Identity = values.Identity,
                Gender = (Gender)genderInt,
                Birthday = values.Birthday,
                EmailConfirmed = true,
                PhoneNumberConfirmed = true,
            };

            // ✅ Create user
            var create = await userManager.CreateAsync(user, password);
            if (!create.Succeeded)
            {
                var msg = string.Join(" ", create.Errors.Select(e => e.Description));
                return Results.Content(
                    BuildRegisterHtml(values.ReturnUrl, null, "create_failed", msg, values),
                    "text/html; charset=utf-8");
            }

            // ✅ Role + Client app
            try
            {
                var addRole = await userManager.AddToRoleAsync(user, "User");
                if (!addRole.Succeeded)
                {
                    var msg = string.Join(" ", addRole.Errors.Select(e => e.Description));
                    await userManager.DeleteAsync(user);
                    return Results.Content(
                        BuildRegisterHtml(values.ReturnUrl, null, "role_failed", $"Failed to add role: {msg}", values),
                        "text/html; charset=utf-8");
                }

                var clientapp = new ApplicationUserAllowedClientView
                {
                    UserId = user.Id,
                    ClientId = "GApplication",
                    IsEnabled = true,
                };

                var addClientResult = await _allowedClient.AddUserToClient(clientapp);

                if (!addClientResult.Succeeded)
                {
                    await userManager.RemoveFromRoleAsync(user, "User");
                    await userManager.DeleteAsync(user);

                    return Results.Content(
                        BuildRegisterHtml(values.ReturnUrl, null, "client_failed", "Failed to attach user to application client.", values),
                        "text/html; charset=utf-8");
                }
            }
            catch (Exception ex)
            {
                try { await userManager.DeleteAsync(user); } catch { }
                return Results.Content(
                    BuildRegisterHtml(values.ReturnUrl, null, "postcreate_failed", $"Post-create step failed: {ex.Message}", values),
                    "text/html; charset=utf-8");
            }

            // ✅ بدل Redirect: صفحة نجاح + إغلاق WebView بعد 4 ثواني
            return Results.Content(
                BuildRegisterSuccessHtml(values.Username, values.Phone),
                "text/html; charset=utf-8");
        })
        .AllowAnonymous();


        // ==============================
        // Helpers
        // ==============================

        static string NormalizeInternationalPhone(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return "";
            var s = input.Trim();

            s = s.Replace(" ", "")
                 .Replace("-", "")
                 .Replace("(", "")
                 .Replace(")", "");

            if (s.StartsWith("00", StringComparison.Ordinal))
                s = "+" + s[2..];

            return s;
        }

        static bool IsValidInternationalPhone(string phone)
            => Regex.IsMatch(phone, @"^\+[1-9]\d{7,14}$", RegexOptions.CultureInvariant);

        static string NormalizeUsername(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return "";
            var s = input.Trim();
            s = s.ToLowerInvariant();
            s = Regex.Replace(s, @"\s+", "");
            s = Regex.Replace(s, @"[^a-z0-9._-]", "");
            return s;
        }

        static bool IsValidUsername(string username)
            => Regex.IsMatch(username, @"^[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])?$", RegexOptions.CultureInvariant);

        static string NormalizeDigitsOnly(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return "";
            return Regex.Replace(input.Trim(), @"[^0-9]", "");
        }

        static bool IsDigitsOnly(string input)
            => Regex.IsMatch(input, @"^[0-9]+$", RegexOptions.CultureInvariant);

        static bool IsAsciiOnly(string input)
        {
            foreach (var ch in input)
            {
                if (ch > 127) return false;
            }
            return true;
        }

        static bool IsValidEmailBasic(string email)
            => Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.CultureInvariant);

        static string Enc(string? s) => WebUtility.HtmlEncode(s ?? "");

        static string BuildSecureBannerHtml()
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

        static string BuildRegisterSuccessHtml(string username, string phone)
        {
            var u = Enc(username);
            var p = Enc(phone);

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
      --gold:#d8c38a;
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.62);
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

    .card {{
      width: 100%;
      max-width: 420px;
      background: linear-gradient(180deg, rgba(20,20,28,0.88), rgba(14,14,18,0.88));
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 16px 18px 22px;
      text-align:center;
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
      text-align:left;
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

    .ok {{
      width: 64px; height: 64px;
      border-radius: 18px;
      margin: 6px auto 14px;
      display:flex; align-items:center; justify-content:center;
      background: rgba(16,185,129,0.12);
      border: 1px solid rgba(16,185,129,0.30);
      font-size: 30px;
    }}
    .title {{
      font-family: Georgia, ""Times New Roman"", serif;
      font-size: 30px;
      margin: 0 0 8px;
      color: var(--gold);
      font-style: italic;
    }}
    .desc {{
      margin: 0 0 16px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }}
    .box {{
      margin: 14px 0;
      padding: 12px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.10);
      background: rgba(255,255,255,0.04);
      text-align:left;
      font-size: 14px;
    }}
    .label {{ color: rgba(255,255,255,0.60); font-size:12px; margin-bottom:4px; }}
    .val {{ color: rgba(255,255,255,0.92); font-weight:700; }}
    .count {{
      margin-top: 16px;
      color: rgba(255,255,255,0.70);
      font-size: 13px;
    }}
    .hint {{
      margin-top: 10px;
      color: rgba(255,255,255,0.45);
      font-size: 12px;
    }}
  </style>
</head>
<body>
  <div class=""card"">
    {BuildSecureBannerHtml()}

    <div class=""ok"">✅</div>
    <div class=""title"">Account Created</div>
    <div class=""desc"">Registration completed successfully. This screen will close automatically.</div>

    <div class=""box"">
      <div class=""label"">Username</div>
      <div class=""val"">{u}</div>
    </div>
    <div class=""box"">
      <div class=""label"">Phone</div>
      <div class=""val"">{p}</div>
    </div>

    <div class=""count"">Closing in <span id=""sec"">4</span> seconds…</div>
    <div class=""hint"">If it doesn’t close, the app should close this WebView.</div>
  </div>

  <script>
    function requestCloseWebView() {{
      var msg = JSON.stringify({{ action: 'close', source: 'register_success' }});

      // ✅ Flutter WebView (webview_flutter) via JavascriptChannel
      try {{
        if (window.CloseWebView && typeof window.CloseWebView.postMessage === 'function') {{
          window.CloseWebView.postMessage(msg);
          return;
        }}
      }} catch(e) {{}}

      // ✅ Flutter InAppWebView (flutter_inappwebview)
      try {{
        if (window.flutter_inappwebview && window.flutter_inappwebview.callHandler) {{
          window.flutter_inappwebview.callHandler('closeWebView', msg);
          return;
        }}
      }} catch(e) {{}}

      // ✅ React Native WebView
      try {{
        if (window.ReactNativeWebView && window.ReactNativeWebView.postMessage) {{
          window.ReactNativeWebView.postMessage(msg);
          return;
        }}
      }} catch(e) {{}}

      // ✅ iOS WKWebView message handler (you must register 'closePage')
      try {{
        if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.closePage) {{
          window.webkit.messageHandlers.closePage.postMessage({{ action:'close', source:'register_success' }});
          return;
        }}
      }} catch(e) {{}}

      // ✅ Android WebView JS interface (you must expose Android.closePage())
      try {{
        if (window.Android && typeof window.Android.closePage === 'function') {{
          window.Android.closePage();
          return;
        }}
      }} catch(e) {{}}

      // ✅ fallback
      try {{ window.close(); }} catch(e) {{}}
    }}

    (function() {{
      var n = 4;
      var el = document.getElementById('sec');

      var timer = setInterval(function() {{
        n--;
        if (el) el.textContent = String(n);
        if (n <= 0) {{
          clearInterval(timer);
          requestCloseWebView();
        }}
      }}, 1000);
    }})();
  </script>
</body>
</html>";
        }

        static string BuildRegisterHtml(string returnUrl, string? ok, string? errCode, string? errMessage, RegisterValues values)
        {
            var okHtml = ok == "created"
                ? """
                  <div class="alert ok">
                    <div class="ico">✅</div>
                    <div class="txt">Account created successfully.</div>
                  </div>
                  """
                : "";

            var errorHtml = string.IsNullOrWhiteSpace(errMessage)
                ? ""
                : $"""
                   <div class="alert err">
                     <div class="ico">⚠️</div>
                     <div class="txt">{Enc(errMessage)}</div>
                   </div>
                   """;

            var safeReturn = Enc(returnUrl);
            var loginLinkReturn = WebUtility.UrlEncode(returnUrl);

            var (ccValue, localValue) = SplitPhone(values.Phone);

            return $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
  <meta charset=""utf-8"" />
  <meta name=""viewport"" content=""width=device-width, initial-scale=1"" />
  <title>Sign Up</title>

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

    * {{ box-sizing: border-box; }}
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

    .phoneFrame {{
      width: 100%;
      max-width: 420px;
      position: relative;
    }}

    .sheet {{
      background: linear-gradient(180deg, rgba(20,20,28,0.88), rgba(14,14,18,0.88));
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
      position: relative;
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

    .row {{
      display:grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }}
    @media (max-width: 460px) {{
      .row {{ grid-template-columns: 1fr; }}
      .title, .title2 {{ font-size: 30px; }}
    }}

    .phoneBox {{
      display:flex;
      align-items:center;
      gap: 10px;
      padding: 12px 12px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: linear-gradient(180deg, var(--field), var(--field2));
    }}
    .ccSelect {{
      width: 120px;
      border: none;
      background: transparent;
      color: rgba(255,255,255,0.92);
      font-size: 15px;
      outline:none;
      appearance: none;
      padding: 6px 6px;
      cursor:pointer;
    }}
    .divider {{
      width:1px;
      height: 28px;
      background: rgba(255,255,255,0.14);
    }}
    .phoneLocal {{
      flex:1;
      border:none;
      background: transparent;
      color: rgba(255,255,255,0.92);
      outline:none;
      font-size: 15px;
      padding: 6px 6px;
    }}
    .phoneLocal::placeholder {{ color: rgba(255,255,255,0.35); }}

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
      {BuildSecureBannerHtml()}

      <div class=""titleRow"">
        <h1 class=""title"">Create</h1>
        <h1 class=""title2"">Account</h1>
      </div>

      <div class=""desc"">
        Create your account securely using our official authentication server.
      </div>

      {okHtml}
      {errorHtml}

      <form id=""regForm"" method=""post"" action=""/account/register"" autocomplete=""off"">
        <input type=""hidden"" name=""returnUrl"" value=""{safeReturn}"" />

        <div class=""row"">
          <div>
            <label>First Name</label>
            <input class=""field"" name=""fname"" value=""{Enc(values.FName)}"" placeholder=""Enter your first name"" required />
          </div>
          <div>
            <label>Last Name</label>
            <input class=""field"" name=""lname"" value=""{Enc(values.LName)}"" placeholder=""Enter your last name"" required />
          </div>
        </div>

        <div class=""row"">
          <div>
            <label>Identity</label>
            <input class=""field"" name=""identity"" id=""identity""
                   value=""{Enc(values.Identity)}""
                   placeholder=""Numbers only""
                   inputmode=""numeric""
                   pattern=""[0-9]+""
                   title=""Digits only""
                   required />
          </div>
          <div>
            <label>Gender</label>
            <select class=""field"" name=""gender"" required>
              <option value="""" {(string.IsNullOrWhiteSpace(values.Gender) ? "selected" : "")}>Select gender</option>
              <option value=""0"" {(values.Gender == "0" ? "selected" : "")}>Male</option>
              <option value=""1"" {(values.Gender == "1" ? "selected" : "")}>Female</option>
            </select>
          </div>
        </div>

        <div class=""row"">
          <div>
            <label>Birthday</label>
            <input class=""field"" type=""date"" name=""birthday"" value=""{Enc(values.Birthday)}"" required />
          </div>
          <div>
            <label>Username</label>
            <input class=""field"" name=""username"" id=""username""
                   value=""{Enc(values.Username)}""
                   placeholder=""username""
                   minlength=""3"" maxlength=""32""
                   title=""Only English letters/numbers and . _ - (3 to 32 chars)""
                   autocomplete=""off""
                   required />
          </div>
        </div>

        <label>Phone Number</label>
        <div class=""phoneBox"">
          <select class=""ccSelect"" name=""cc"" id=""cc"">
            <option value=""+90"" {(ccValue == "+90" ? "selected" : "")}>🇹🇷 +90</option>
            <option value=""+963"" {(ccValue == "+963" ? "selected" : "")}>🇸🇾 +963</option>
            <option value=""+20"" {(ccValue == "+20" ? "selected" : "")}>🇪🇬 +20</option>
            <option value=""+971"" {(ccValue == "+971" ? "selected" : "")}>🇦🇪 +971</option>
            <option value=""+966"" {(ccValue == "+966" ? "selected" : "")}>🇸🇦 +966</option>
          </select>
          <div class=""divider""></div>
          <input class=""phoneLocal"" name=""phone_local"" id=""phone_local""
                 value=""{Enc(localValue)}""
                 placeholder=""Enter your number"" inputmode=""numeric"" />
        </div>

        <input type=""hidden"" name=""phone"" id=""phone"" value=""{Enc(values.Phone)}"" />

        <label>Email Address</label>
        <input class=""field"" type=""email"" name=""email"" id=""email""
               value=""{Enc(values.Email)}""
               placeholder=""Enter your email""
               inputmode=""email""
               autocomplete=""off""
               required />

        <label>Password</label>
        <div class=""pwdWrap"">
          <input class=""field"" id=""pwd"" type=""password"" name=""password"" placeholder=""••••••••"" required />
          <button class=""eye"" type=""button"" onclick=""togglePwd('pwd')"" aria-label=""Show password"">👁</button>
        </div>

        <label>Confirm Password</label>
        <div class=""pwdWrap"">
          <input class=""field"" id=""cpwd"" type=""password"" name=""confirm"" placeholder=""••••••••"" required />
          <button class=""eye"" type=""button"" onclick=""togglePwd('cpwd')"" aria-label=""Show confirm password"">👁</button>
        </div>

        <div class=""actionBar"">
          <button class=""btnGold"" type=""submit"">SIGN UP</button>
          <button class=""go"" type=""submit"" aria-label=""Submit"">›</button>
        </div>

        <div class=""below"">
          Already Have An Account ? <a href=""/account/login?returnUrl={loginLinkReturn}"">LOGIN</a>
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
      var form = document.getElementById('regForm');
      var username = document.getElementById('username');
      var identity = document.getElementById('identity');
      var email = document.getElementById('email');
      var hiddenPhone = document.getElementById('phone');

      if (username) {{
        username.addEventListener('input', function() {{
          var v = username.value || '';
          v = v.toLowerCase();
          v = v.replace(/\\s+/g, '');
          v = v.replace(/[^a-z0-9._-]/g, '');
          username.value = v;
        }});
      }}

      if (identity) {{
        identity.addEventListener('input', function() {{
          var v = identity.value || '';
          v = v.replace(/[^0-9]/g, '');
          identity.value = v;
        }});
      }}

      if (email) {{
        email.addEventListener('input', function() {{
          var v = email.value || '';
          v = v.replace(/[^\x00-\x7F]/g, '');
          email.value = v;
        }});
      }}

      if (!form) return;

      form.addEventListener('submit', function() {{
        var cc = (document.getElementById('cc')?.value || '').trim();
        var local = (document.getElementById('phone_local')?.value || '').trim();
        local = local.replace(/[^0-9]/g, '');
        var full = (cc + local).replace(/\\s+/g, '');

        if (hiddenPhone) {{
          if (local.length > 0) hiddenPhone.value = full;
          else hiddenPhone.value = (hiddenPhone.value || '').trim();
        }}
      }});
    }})();
  </script>
</body>
</html>";
        }

        static (string cc, string local) SplitPhone(string phone)
        {
            if (string.IsNullOrWhiteSpace(phone))
                return ("+90", "");

            if (!phone.StartsWith("+"))
                return ("+90", phone);

            var codes = new[] { "+963", "+971", "+966", "+90", "+20" };

            foreach (var code in codes)
            {
                if (phone.StartsWith(code, StringComparison.Ordinal))
                {
                    var local = phone.Substring(code.Length);
                    return (code, local);
                }
            }

            if (phone.Length >= 4)
                return (phone.Substring(0, 4), phone.Substring(4));

            return ("+90", phone.TrimStart('+'));
        }
    }
}

file sealed class RegisterValues
{
    public string FName { get; set; } = "";
    public string LName { get; set; } = "";
    public string Identity { get; set; } = "";
    public string Gender { get; set; } = "";
    public string Birthday { get; set; } = "";
    public string Phone { get; set; } = "";
    public string Email { get; set; } = "";
    public string Username { get; set; } = "";
    public string ReturnUrl { get; set; } = "/";
}
/*

كيف تلتقط “إغلاق WebView” داخل التطبيق (مختصر)
   Flutter (webview_flutter) — JavaScriptChannel
   لازم تسمي القناة CloseWebView (مثل ما استدعيناها بالكود):
   عندما تستقبل message فيها { action: 'close' } → سكّر الـ WebView / Pop الصفحة.
   iOS WKWebView
   سجّل message handler باسم closePage:
   window.webkit.messageHandlers.closePage.postMessage(...)
   Android WebView
   عرّف JS Interface باسم Android وفيه دالة:
   Android.closePage()
*/