using Microsoft.AspNetCore.Http;
using System.Net;

namespace IdentityServerNSY.account;

public static class ClientErrorPages
{
    public static IResult Html(string title, string message, string? clientId = null, int statusCode = 400)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

        var html = $@"
<!doctype html>
<html lang=""en"">
<head>
  <meta charset=""utf-8"" />
  <meta name=""viewport"" content=""width=device-width,initial-scale=1"" />
  <title>{E(title)}</title>
  <style>
    body {{
      margin:0; height:100vh; display:flex; align-items:center; justify-content:center;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial;
      background:linear-gradient(135deg,#111827,#1f2937,#0b1220);
    }}
    .card {{
      width:min(760px,92vw); background:#fff; border-radius:16px; padding:26px 22px;
      box-shadow:0 30px 70px rgba(0,0,0,.45);
    }}
    h2 {{ margin:0 0 10px; }}
    p {{ margin:8px 0; color:#374151; line-height:1.5; }}
    code {{ background:#f3f4f6; padding:2px 6px; border-radius:8px; }}
    .btns {{ display:flex; gap:10px; justify-content:flex-end; margin-top:18px; flex-wrap:wrap; }}
    button {{ border:0; border-radius:10px; padding:12px 14px; font-weight:700; cursor:pointer; }}
    .danger {{ background:#ef4444; color:#fff; }}
    .muted {{ background:#e5e7eb; color:#111827; }}
    .small {{ font-size:12px; color:#6b7280; margin-top:10px; }}
  </style>
</head>
<body>
  <div class=""card"">
    <h2>❌ {E(title)}</h2>
    <p>{E(message)}</p>

    {(string.IsNullOrWhiteSpace(clientId) ? "" : $@"<p><b>ClientId:</b> <code>{E(clientId)}</code></p>")}

    <div class=""btns"">
      <button class=""muted"" onclick=""history.back()"">Go Back</button>
      <button class=""danger"" id=""logoutBtn"">Logout</button>
    </div>

    <div class=""small"">This page provides a safe logout if the authorization request is invalid.</div>
  </div>

  <script>
    document.getElementById('logoutBtn').onclick = async () => {{
      try {{
        await fetch('/account/logoutcode', {{
          method: 'POST',
          credentials: 'include',
          headers: {{ 'Content-Type': 'application/json' }},
          body: '{{}}'
        }});
      }} catch (e) {{}}
      location.replace('/logout-success');
    }};
  </script>
</body>
</html>";

        return Results.Content(html, "text/html; charset=utf-8", statusCode: statusCode);
    }
}
