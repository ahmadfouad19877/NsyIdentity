using System.Net;
using IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityServerNSY.account;

public static class SetPasswordEndPoint
{
    public static void MapSetPasswordEndpoints(this WebApplication app)
    {
        // ==============================
        // GET: Render Set Password Page
        // ==============================
        app.MapGet("/account/set-password", (
            string? uid,
            string? t,
            string? returnUrl,
            string? ok,
            string? errCode,
            string? errMessage) =>
        {
            returnUrl = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;

            // Minimal validation
            if (string.IsNullOrWhiteSpace(uid) || string.IsNullOrWhiteSpace(t))
            {
                return Results.Content(
                    BuildSetPasswordHtml(
                        returnUrl: returnUrl,
                        ok: null,
                        errCode: "missing",
                        errMessage: "Invalid link. Missing parameters.",
                        values: new SetPasswordValues { UserId = uid ?? "", Token = t ?? "" }),
                    "text/html; charset=utf-8");
            }

            return Results.Content(
                BuildSetPasswordHtml(
                    returnUrl: returnUrl,
                    ok: ok,
                    errCode: errCode,
                    errMessage: errMessage,
                    values: new SetPasswordValues { UserId = uid, Token = t, ReturnUrl = returnUrl }),
                "text/html; charset=utf-8");
        }).AllowAnonymous();


        // ==============================
        // POST: Set Password
        // ==============================
        app.MapPost("/account/set-password", async (
            HttpContext http,
            UserManager<ApplicationUser> userManager) =>
        {
            var form = await http.Request.ReadFormAsync();

            var values = new SetPasswordValues
            {
                UserId = form["uid"].ToString().Trim(),
                Token = form["t"].ToString().Trim(),
                ReturnUrl = form["returnUrl"].ToString().Trim()
            };

            var password = form["password"].ToString();
            var confirm = form["confirm"].ToString();

            values.ReturnUrl = string.IsNullOrWhiteSpace(values.ReturnUrl) ? "/" : values.ReturnUrl;

            // Required
            if (string.IsNullOrWhiteSpace(values.UserId) ||
                string.IsNullOrWhiteSpace(values.Token) ||
                string.IsNullOrWhiteSpace(password) ||
                string.IsNullOrWhiteSpace(confirm))
            {
                return Results.Content(
                    BuildSetPasswordHtml(values.ReturnUrl, null, "missing", "Please fill in all required fields.", values),
                    "text/html; charset=utf-8");
            }

            if (!string.Equals(password, confirm, StringComparison.Ordinal))
            {
                return Results.Content(
                    BuildSetPasswordHtml(values.ReturnUrl, null, "pwd_mismatch", "Password and Confirm Password do not match.", values),
                    "text/html; charset=utf-8");
            }

            // Find user
            var user = await userManager.FindByIdAsync(values.UserId);
            if (user is null)
            {
                return Results.Content(
                    BuildSetPasswordHtml(values.ReturnUrl, null, "user_not_found", "User not found.", values),
                    "text/html; charset=utf-8");
            }

            // Decode token from Base64Url (IMPORTANT)
            string decodedToken;
            try
            {
                decodedToken = DecodeToken(values.Token);
            }
            catch
            {
                return Results.Content(
                    BuildSetPasswordHtml(values.ReturnUrl, null, "token_invalid", "Invalid or corrupted token.", values),
                    "text/html; charset=utf-8");
            }

            // Set password using ResetPassword token
            var reset = await userManager.ResetPasswordAsync(user, decodedToken, password);
            if (!reset.Succeeded)
            {
                var msg = string.Join(" ", reset.Errors.Select(e => e.Description));
                return Results.Content(
                    BuildSetPasswordHtml(values.ReturnUrl, null, "set_failed", msg, values),
                    "text/html; charset=utf-8");
            }

            // Optional: confirm email/phone if you want
            // user.EmailConfirmed = true;
            // user.PhoneNumberConfirmed = true;
            // await userManager.UpdateAsync(user);

            // Success page (auto close)
            return Results.Content(
                BuildSetPasswordSuccessHtml(),
                "text/html; charset=utf-8");
        })
        .AllowAnonymous();


        // ==============================
        // Helpers
        // ==============================

        static string Enc(string? s) => WebUtility.HtmlEncode(s ?? "");

        static string EncodeToken(string token)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(token);
            return WebEncoders.Base64UrlEncode(bytes);
        }

        static string DecodeToken(string encoded)
        {
            var bytes = WebEncoders.Base64UrlDecode(encoded);
            return System.Text.Encoding.UTF8.GetString(bytes);
        }

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

        static string BuildSetPasswordSuccessHtml()
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
      --bg0:#050507; --bg1:#0b0b10;
      --gold:#d8c38a;
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.62);
      --shadow: 0 22px 60px rgba(0,0,0,0.65);
      --radius: 26px;
    }}
    * {{ box-sizing:border-box; }}
    body {{
      margin:0; min-height:100vh;
      display:flex; align-items:center; justify-content:center;
      background:
        radial-gradient(900px 500px at 25% 15%, rgba(216,195,138,0.10), transparent 55%),
        radial-gradient(700px 500px at 80% 35%, rgba(255,255,255,0.06), transparent 60%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, ""Segoe UI"", Roboto, Arial;
      padding: 28px 18px;
    }}
    .card {{
      width:100%; max-width:420px;
      background: linear-gradient(180deg, rgba(20,20,28,0.88), rgba(14,14,18,0.88));
      border: 1px solid rgba(255,255,255,0.10);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 16px 18px 22px;
      text-align:center;
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
    <div class=""title"">Password Updated</div>
    <div class=""desc"">Your password has been set successfully. This screen will close automatically.</div>
    <div class=""count"">Closing in <span id=""sec"">4</span> seconds…</div>
    <div class=""hint"">If it doesn’t close, the app should close this WebView.</div>
  </div>

  <script>
    function requestCloseWebView() {{
      var msg = JSON.stringify({{ action: 'close', source: 'set_password_success' }});

      try {{
        if (window.CloseWebView && typeof window.CloseWebView.postMessage === 'function') {{
          window.CloseWebView.postMessage(msg); return;
        }}
      }} catch(e) {{}}

      try {{
        if (window.flutter_inappwebview && window.flutter_inappwebview.callHandler) {{
          window.flutter_inappwebview.callHandler('closeWebView', msg); return;
        }}
      }} catch(e) {{}}

      try {{
        if (window.ReactNativeWebView && window.ReactNativeWebView.postMessage) {{
          window.ReactNativeWebView.postMessage(msg); return;
        }}
      }} catch(e) {{}}

      try {{
        if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.closePage) {{
          window.webkit.messageHandlers.closePage.postMessage({{ action:'close', source:'set_password_success' }}); return;
        }}
      }} catch(e) {{}}

      try {{
        if (window.Android && typeof window.Android.closePage === 'function') {{
          window.Android.closePage(); return;
        }}
      }} catch(e) {{}}

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

        static string BuildSetPasswordHtml(
            string returnUrl,
            string? ok,
            string? errCode,
            string? errMessage,
            SetPasswordValues values)
        {
            var okHtml = ok == "done"
                ? """
                  <div class="alert ok">
                    <div class="ico">✅</div>
                    <div class="txt">Password updated successfully.</div>
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

            return $@"
<!DOCTYPE html>
<html lang=""en"">
<head>
  <meta charset=""utf-8"" />
  <meta name=""viewport"" content=""width=device-width, initial-scale=1"" />
  <title>Set Password</title>

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
  </style>
</head>

<body>
  <div class=""phoneFrame"">
    <div class=""sheet"">
      {BuildSecureBannerHtml()}

      <div class=""titleRow"">
        <h1 class=""title"">Set</h1>
        <h1 class=""title2"">Password</h1>
      </div>

      <div class=""desc"">
        Please choose a strong password for your account.
      </div>

      {okHtml}
      {errorHtml}

      <form id=""setForm"" method=""post"" action=""/account/set-password"" autocomplete=""off"">
        <input type=""hidden"" name=""uid"" value=""{Enc(values.UserId)}"" />
        <input type=""hidden"" name=""t"" value=""{Enc(values.Token)}"" />
        <input type=""hidden"" name=""returnUrl"" value=""{safeReturn}"" />

        <label>New Password</label>
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
          <button class=""btnGold"" type=""submit"">SAVE</button>
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
  </script>
</body>
</html>";
        }
    }
}

file sealed class SetPasswordValues
{
    public string UserId { get; set; } = "";
    public string Token { get; set; } = "";
    public string ReturnUrl { get; set; } = "/";
}
