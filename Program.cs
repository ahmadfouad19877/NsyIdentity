using System.Text;
using IdentityServerNSY.Interface;
using IdentityServerNSY.Interface.ImageService;
using IdentityServerNSY.Middleware;
using IdentityServerNSY.Models;
using IdentityServerNSY.account;
using IdentityServerNSY.Infrastructure.Seed;
using IdentityServerNSY.Security.Sherd;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Versioning;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

//
// ============================
// 1) Controllers + Swagger
// ============================
//
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

//
// ============================
// 2) CORS (Allow all origins بشكل آمن مع Credentials عبر SetIsOriginAllowed)
// ============================
//
const string CorsPolicyName = "AppCors";

var allowedOriginsRaw =
    AppSecrets.TryGet("ALLOWED_ORIGINS")
    ?? builder.Configuration["Cors:AllowedOrigins"]
    ?? throw new Exception("ALLOWED_ORIGINS is not configured (AppSecrets or appsettings).");

var allowedOrigins = allowedOriginsRaw
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
    .Distinct(StringComparer.OrdinalIgnoreCase)
    .ToArray();

builder.Services.AddCors(options =>
{
    options.AddPolicy(CorsPolicyName, policy =>
    {
        policy.WithOrigins(allowedOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

//
// ============================
// 3) Connection String (ENV -> Docker Secret File -> appsettings)
// ============================
//
builder.Services.AddDbContext<ApplicationDb>(options =>
{
    var connectionString =
        AppSecrets.TryGet("DB_CONNECTION")
        ?? builder.Configuration.GetConnectionString("DefaultConnection")
        ?? throw new Exception("DB connection is missing (AppSecrets or DefaultConnection).");

    options.UseSqlServer(connectionString, sql =>
    {
        sql.EnableRetryOnFailure(5, TimeSpan.FromSeconds(10), null);
        sql.CommandTimeout(60);
    });

    // options.EnableSensitiveDataLogging();
    // options.EnableDetailedErrors();
});

//
// ============================
// 5) ASP.NET Identity
// ============================
//
builder.Services
    .AddIdentity<ApplicationUser, ApplicationRole>(options =>
    {
        options.SignIn.RequireConfirmedPhoneNumber = false;

        // Password policy (خفيفة حسب إعدادك الحالي)
        options.Password.RequireDigit = false;
        options.Password.RequiredLength = 3;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireLowercase = false;
    })
    .AddEntityFrameworkStores<ApplicationDb>()
    .AddDefaultTokenProviders();

// مسار صفحة تسجيل الدخول للـ Cookie (لو عندك UI/Endpoints)
builder.Services.ConfigureApplicationCookie(o =>
{
    o.LoginPath = "/account/login";
});

//
// ============================
// 6) Authentication Schemes
//    - Default: OpenIddict Validation (Bearer)
//    - SignIn: Cookie Identity (للـ login)
// ============================
//
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

    // SignIn للكوكي فقط
    options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
});

//
// ============================
// 7) OpenIddict (Core + Server + Validation)
// ============================
//
var issuer =
    AppSecrets.TryGet("OPENIDDICT_ISSUER")
    ?? builder.Configuration["OpenIddict:Issuer"]
    ?? throw new Exception("OpenIddict Issuer is missing.");
builder.Services.AddOpenIddict()

    // Core: storage via EF Core
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDb>();
    })

    // Server: token/authorize/introspect endpoints
    .AddServer(options =>
    {
        // Issuer (لازم يطابق الدومين اللي المستخدمين/الـ APIs تعتمد عليه)
        options.SetIssuer(new Uri(issuer));

        // Endpoints
        options
            .SetTokenEndpointUris("/connect/token")
            .SetAuthorizationEndpointUris("/connect/authorize")
            .SetIntrospectionEndpointUris("/connect/introspect");

        // Flows
        options
            .AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowRefreshTokenFlow();

        // Scopes
        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.OfflineAccess, // مهم للـ refresh token
            "local_app_api",
            "GApplication",
            "WebApplication"
        );

        // Dev certificates (للتطوير فقط)
        options
            .AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        // ASP.NET Core integration
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough();
        // ملاحظة: انت كنت حاذف EnableTokenEndpointPassthrough — خليته محذوف فعلاً

        // Reference tokens (opaque)
        options.UseReferenceAccessTokens();
        options.UseReferenceRefreshTokens();

        // Lifetimes
        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15));
        options.SetRefreshTokenLifetime(TimeSpan.FromDays(30));

        // Custom event handlers (حسب مشروعك)
        options.AddEventHandler<OpenIddictServerEvents.ValidateTokenRequestContext>(b =>
            b.UseScopedHandler<RequireDeviceHeadersOnTokenRequestHandler>());

        options.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(b =>
            b.UseScopedHandler<StoreSessionOnTokenHandler>());

        // Logging بسيط لطلبات introspection (اختياري)
        options.AddEventHandler<OpenIddictServerEvents.ValidateIntrospectionRequestContext>(b =>
            b.UseInlineHandler(ctx =>
            {
                Console.WriteLine($"INTROSPECT token: {ctx.Request.Token}");
                Console.WriteLine($"INTROSPECT client_id: {ctx.Request.ClientId}");
                return default;
            }));
    })

    // Validation: يخلي [Authorize] يشتغل على نفس السيرفر
    .AddValidation(options =>
    {
        options.SetIssuer("https://nsyuser.i-myapp.com");
        options.UseLocalServer();
        options.UseAspNetCore();
    });

//
// ============================
// 8) Authorization Policies
// ============================
//
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("SuperAdmin", policy =>
    {
        // إجبار استخدام Validation scheme
        policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);

        // لازم يكون Authenticated
        policy.RequireAuthenticatedUser();

        // تحقق Scope سواء scope (string واحد) أو scp (claims متعددة)
        policy.RequireAssertion(ctx =>
        {
            var scopeValue = ctx.User.FindFirst("scope")?.Value; // "a b c"
            var scopesFromScope = string.IsNullOrWhiteSpace(scopeValue)
                ? Array.Empty<string>()
                : scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            var scopesFromScp = ctx.User.FindAll("scp").Select(x => x.Value);

            return scopesFromScope.Concat(scopesFromScp).Contains("local_app_api");
        });

        // client id عبر azp
        policy.RequireClaim("azp", "PostmanLocal");

        // role
        policy.RequireRole("SuperAdmin");
    });
});

//
// ============================
// 9) DI registrations (Services/Repos/Handlers)
// ============================
//
builder.Services.AddHttpClient();

// OpenIddict handlers
builder.Services.AddScoped<RequireDeviceHeadersOnTokenRequestHandler>();
builder.Services.AddScoped<StoreSessionOnTokenHandler>();

// Repos / Services
builder.Services.AddTransient<IRoleRep, RoleRep>();
builder.Services.AddTransient<IMangeUserBySuperAdmin, MangeUserBySuperAdmin>();
builder.Services.AddTransient<IProtectText, ProtectText>();
builder.Services.AddTransient<IUserAllowedClientRep, UserAllowedClientRep>();
builder.Services.AddTransient<IUserSessionRep, UserSessionRep>();
builder.Services.AddTransient<IClientIdRep, ClientIdRep>();
builder.Services.AddTransient<IClientAllowedAud, ClientAllowedAud>();

builder.Services.AddTransient<IImageService, ImageService>();

//
// ============================
// 10) API Versioning (Url segment /api/v{version}/...)
// ============================
//
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;

    // قراءة النسخة من المسار
    options.ApiVersionReader = ApiVersionReader.Combine(new UrlSegmentApiVersionReader());
});

//
// ============================
// 11) Kestrel TLS (TLS 1.2 فقط)
// ============================
//
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
    });
});

//
// ============================
// 12) Session (Memory cache + session)
// ============================
//
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();

//
// ============================
// 13) Forwarded Headers (Reverse proxy / load balancer)
// ============================
//
var forwardedHeadersOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor
                     | ForwardedHeaders.XForwardedProto
                     | ForwardedHeaders.XForwardedHost
};
forwardedHeadersOptions.KnownNetworks.Clear();
forwardedHeadersOptions.KnownProxies.Clear();

var app = builder.Build();

//
// ============================
// 14) Middleware pipeline
// ============================
//
app.UseForwardedHeaders(forwardedHeadersOptions);

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseCors(CorsPolicyName);

app.UseSession();

app.UseAuthentication();

//
// تحقق الجلسة/الجهاز حسب Middleware الخاص بك
//
app.UseSessionValidation(opt =>
{
    opt.DeviceIdHeader = "X-Device-Id";
    opt.DeviceNameHeader = "X-Device-Name";
    opt.PlatformHeader = "X-Platform";

    opt.EnforceDeviceHeadersOnApiPaths = true;
    opt.ApiPrefix = "/api";

    opt.UpdateLastSeen = true;
});

app.UseAuthorization();

//
// ============================
// 15) Seeding (Roles/Users/Clients)
// ============================
//
await IdentitySeed.SeedAsync(app.Services);

// Clients seed حسب Docker env
if (Environment.GetEnvironmentVariable("IS_DOCKER") == "true")
{
    await OpenIddictClientsSeedServer.SeedAsync(app.Services);
}
else
{
    await OpenIddictClientsSeed.SeedAsync(app.Services);
}

//
// ============================
// 16) Endpoints mapping
// ============================
//
app.MapAccountEndpoints();
app.MapLogoutEndPoint();
app.MapRegisterEndpoints();
app.MapSetPasswordEndpoints();

app.MapControllers();

app.MapGet("/", () => "Hello from IdentityApp!");

app.Run();