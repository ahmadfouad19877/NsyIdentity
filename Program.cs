
using System.Text;
using IdentityServer.Interface;
using IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using IdentityServer.Interface.ImageService;
using IdentityServer.Middleware;
using IdentityServerNSY.account;
using IdentityServerNSY.Infrastructure.Seed;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Versioning;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation.AspNetCore;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
string MyAllowSpecificOrigins = "*";
// Configure the HTTP request pipeline.
builder.Services.AddCors(options =>
{
    options.AddPolicy(MyAllowSpecificOrigins,
    builder =>
    {
        builder.SetIsOriginAllowed(isOriginAllowed: _ => true).AllowAnyHeader().AllowAnyMethod().AllowCredentials();
    });
});
// 1) حاول من Environment مباشرة (اختياري)
var connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION");

// 2) أولوية أعلى: Docker Secret file
var connectionFile = Environment.GetEnvironmentVariable("DB_CONNECTION_FILE");
if (!string.IsNullOrWhiteSpace(connectionFile) && File.Exists(connectionFile))
{
    connectionString = File.ReadAllText(connectionFile, Encoding.UTF8).Trim();
}

// 3) fallback من appsettings (مثلاً للتشغيل المحلي)
if (string.IsNullOrWhiteSpace(connectionString))
{
    connectionString = builder.Configuration.GetConnectionString("MyConnection");
}

if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException("DB connection string is missing.");
}

builder.Services.AddDbContext<ApplicationDb>(options =>
    options.UseSqlServer(connectionString));

//builder.Services.AddDbContext<ApplicationDb>(option => option.UseSqlServer(builder.Configuration.GetConnectionString("MyConnection")));
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    //options.SignIn.RequireConfirmedEmail = false;
    options.SignIn.RequireConfirmedPhoneNumber = false;
    options.Password.RequireDigit = false;
    options.Password.RequiredLength = 3;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;

}).AddEntityFrameworkStores<ApplicationDb>().AddDefaultTokenProviders();
builder.Services.ConfigureApplicationCookie(o =>
{
    o.LoginPath = "/account/login"; // عندك endpoint login
});
builder.Services.AddAuthentication(options =>
{
    //options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    //options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
    //options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
    // ✅ هذا يخلي [Authorize] يفهم Bearer tokens (OpenIddict Validation)
    options.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

    // يبقى للكوكي فقط عند SignIn من صفحة /account/login
    options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
});

builder.Services.AddOpenIddict()
    // الطبقة الأساسية + EF Core
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<ApplicationDb>();
    })

    // سيرفر التوكن (بديل IdentityServer)
    .AddServer(options =>
    {
        // الـ Issuer (نفس الدومين اللي كنت حاطه في IdentityServer)
        options.SetIssuer(new Uri("https://nsyuser.i-myapp.com"));
        //options.SetIssuer(new Uri("https://localhost:7266"));
        // أنواع الـ Flows اللي بدك تدعمها
        /*
         * هذا يسمح باستخدام Password Flow
           يعني التطبيق يرسل اسم المستخدم + كلمة السر مباشرة لسيرفر الهوية.
         */
        
        // Endpoints
        options
            .SetTokenEndpointUris("/connect/token")
            .SetAuthorizationEndpointUris("/connect/authorize")
            .SetIntrospectionEndpointUris("/connect/introspect");
        
        options.AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowRefreshTokenFlow();
        // لو حاب تضيف Code + PKCE بعدين:
        //.AllowPasswordFlow()
        // .AllowAuthorizationCodeFlow()
        // .RequireProofKeyForCodeExchange();
        
        
        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.OfflineAccess, // ✅ مهم
            "local_app_api",
            "GApplication",
            "WebApplication"
        );
        // شهادات التوقيع والتشفير (للتجارب / التطوير)
        options
            .AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        // ربطه مع ASP.NET Core (يرجع JSON جاهز من الـ endpoints)
        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough();
            //.EnableTokenEndpointPassthrough();
        // احذف EnableTokenEndpointPassthrough
        
        // ✅ يخلي access_token يطلع opaque (reference token)
        options.UseReferenceAccessTokens();

        // (اختياري) يخلي refresh_token كمان reference
        options.UseReferenceRefreshTokens();
        // Access Token: 15 دقيقة
        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15));

        // Refresh Token: 30 يوم
        options.SetRefreshTokenLifetime(TimeSpan.FromDays(30));
        
        options.AddEventHandler<OpenIddictServerEvents.ValidateTokenRequestContext>(b =>
            b.UseScopedHandler<RequireDeviceHeadersOnTokenRequestHandler>());

        options.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(b =>
            b.UseScopedHandler<StoreSessionOnTokenHandler>());
        
        options.AddEventHandler<OpenIddictServerEvents.ValidateIntrospectionRequestContext>(b =>
            b.UseInlineHandler(ctx =>
            {
                Console.WriteLine($"INTROSPECT token: {ctx.Request.Token}");
                Console.WriteLine($"INTROSPECT client_id: {ctx.Request.ClientId}");
                return default;
            }));


    })

    // Validation (تحتاجها لو نفس السيرفر فيه APIs محمية)
    .AddValidation(options =>
    {
        options.SetIssuer("https://nsyuser.i-myapp.com");
        //options.SetIssuer(new Uri("https://localhost:7266"));
        options.UseLocalServer();   // يتحقق من التوكنات الصادرة من نفس السيرفر
        options.UseAspNetCore();    // يربط مع [Authorize]
    });




builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("SuperAdmin", policy =>
    {
        Console.WriteLine("EEEE");
        policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        
        policy.RequireAuthenticatedUser();

        // ✅ تحقق من السكوب سواء كان "scope" أو "scp"
        policy.RequireAssertion(ctx =>
        {
            var scopeValue = ctx.User.FindFirst("scope")?.Value; // "a b c"
            var scopesFromScope = string.IsNullOrWhiteSpace(scopeValue)
                ? Array.Empty<string>()
                : scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            var scopesFromScp = ctx.User.FindAll("scp").Select(x => x.Value); // claims متعددة

            return scopesFromScope.Concat(scopesFromScp)
                .Contains("local_app_api");
        });

        // ✅ بدل client_id استخدم azp (Authorized Party)
        policy.RequireClaim("azp", "PostmanLocal");

        // ✅ Roles
        policy.RequireRole("SuperAdmin");
    });
    
});
builder.Services.AddHttpClient();
builder.Services.AddScoped<RequireDeviceHeadersOnTokenRequestHandler>();
builder.Services.AddScoped<StoreSessionOnTokenHandler>();
builder.Services.AddTransient<IRoleRep, RoleRep>();
builder.Services.AddTransient<IMangeUserBySuperAdmin, MangeUserBySuperAdmin>();
builder.Services.AddTransient<IProtectText, ProtectText>();
builder.Services.AddTransient<IUserAllowedClientRep, UserAllowedClientRep>();
builder.Services.AddTransient<IUserSessionRep, UserSessionRep>();
builder.Services.AddTransient<IClientIdRep, ClientIdRep>();
builder.Services.AddTransient<IImageService, ImageService>();

builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0); // النسخة الافتراضية v1.0
    options.AssumeDefaultVersionWhenUnspecified = true; // لو ما حدد النسخة، يستخدم v1
    options.ReportApiVersions = true; // يظهر النسخ المدعومة في الهيدر
    options.ApiVersionReader = ApiVersionReader.Combine(
        new UrlSegmentApiVersionReader()
    );  // اقرأ النسخة من المسار
});
if (Environment.GetEnvironmentVariable("IS_DOCKER") == "true")
{
    builder.WebHost.UseUrls("http://0.0.0.0:5015");
}
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
    });
});
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(); 
var forwardedHeadersOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
};
forwardedHeadersOptions.KnownNetworks.Clear();
forwardedHeadersOptions.KnownProxies.Clear();
var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseForwardedHeaders(forwardedHeadersOptions);
app.UseCors(MyAllowSpecificOrigins);

app.UseSession();
app.UseAuthentication();
//لفحص التوكن
/*app.Use(async (context, next) =>
{
    Console.WriteLine("MMMMMM");
    Console.WriteLine(context.Response.HttpContext.User.Identity.Name);
    // هل المستخدم مصادق؟
    if (context.User?.Identity?.IsAuthenticated == true)
    {
        // 🔹 التوكن الخام (Bearer)
        var authHeader = context.Request.Headers["Authorization"].ToString();
        var token = authHeader.StartsWith("Bearer ")
            ? authHeader.Substring("Bearer ".Length)
            : null;

        Console.WriteLine("🔐 Access Token:");
        Console.WriteLine(token);

        // 🔹 قراءة Claims (الأهم)
        Console.WriteLine("👤 Claims:");
        foreach (var claim in context.User.Claims)
        {
            Console.WriteLine($"- {claim.Type} = {claim.Value}");
        }

        // أمثلة استخدام مباشرة
        var userId = context.User.FindFirst("sub")?.Value;
        var clientId = context.User.FindFirst("azp")?.Value;
        var roles = context.User.FindAll("role").Select(r => r.Value);

        Console.WriteLine($"UserId: {userId}");
        Console.WriteLine($"ClientId (azp): {clientId}");
        Console.WriteLine($"Roles: {string.Join(",", roles)}");
    }

    await next();
});*/
app.UseSessionValidation(opt =>
{
    opt.DeviceIdHeader = "X-Device-Id";
    opt.DeviceNameHeader = "X-Device-Name";
    opt.PlatformHeader = "X-Platform";

    opt.EnforceDeviceHeadersOnApiPaths = true;
    opt.ApiPrefix = "/api"; // عدّلها إذا مساراتك مختلفة

    opt.UpdateLastSeen = true;
});

app.UseAuthorization();
//app.UseMiddleware<EnforceClientIdMiddleware>("SultanUrfaAdmin");
// ✅ هون بالضبط: Seed Roles + Users
await IdentitySeed.SeedAsync(app.Services);
if (Environment.GetEnvironmentVariable("IS_DOCKER") == "true")
{
    await OpenIddictClientsSeedServer.SeedAsync(app.Services);
   
}
else
{
    await OpenIddictClientsSeed.SeedAsync(app.Services);
}


app.MapAccountEndpoints();
app.MapLogoutEndPoint();
app.MapRegisterEndpoints();
app.MapSetPasswordEndpoints();
app.MapControllers();
app.MapGet("/", () => "Hello from   IdentityApp!");
app.Run();

//مكتبة للتحقق
//OpenIddict.Validation.AspNetCore
/*
 
builder.Services.AddAuthentication(options =>
   {
       options.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
       options.DefaultChallengeScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
   });
   builder.Services.AddAuthorization(options =>
   {
       options.AddPolicy("SuperAdmin", policy =>
       {
           Console.WriteLine("EEEE");
           policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
           
           policy.RequireAuthenticatedUser();
   
           // ✅ تحقق من السكوب سواء كان "scope" أو "scp"
           policy.RequireAssertion(ctx =>
           {
               var scopeValue = ctx.User.FindFirst("scope")?.Value; // "a b c"
               var scopesFromScope = string.IsNullOrWhiteSpace(scopeValue)
                   ? Array.Empty<string>()
                   : scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries);
   
               var scopesFromScp = ctx.User.FindAll("scp").Select(x => x.Value); // claims متعددة
   
               return scopesFromScope.Concat(scopesFromScp)
                   .Contains("local_app_api");
           });
   
           // ✅ بدل client_id استخدم azp (Authorized Party)
           policy.RequireClaim("azp", "PostmanLocal");
   
           // ✅ Roles
           policy.RequireRole("SuperAdmin");
       });
       
   });
 *
 *
 * 
 */







/*
 * app.MapGet("/connect/authorize", async (HttpContext httpContext) =>
   {
       if (httpContext.User?.Identity?.IsAuthenticated != true)
       {
           return Results.Challenge(
               new AuthenticationProperties
               {
                   RedirectUri = httpContext.Request.PathBase + httpContext.Request.Path + httpContext.Request.QueryString
               },
               authenticationSchemes: new[] { IdentityConstants.ApplicationScheme });
       }
   
       var request = httpContext.GetOpenIddictServerRequest()
                    ?? throw new InvalidOperationException("OpenIddict request is missing.");
   
       var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
   
       // sub
       var userId =
           httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ??
           httpContext.User.FindFirstValue(OpenIddictConstants.Claims.Subject);
   
       if (!string.IsNullOrEmpty(userId))
           identity.AddClaim(OpenIddictConstants.Claims.Subject, userId);
   
       // name
       var name = httpContext.User.Identity?.Name;
       if (!string.IsNullOrEmpty(name))
           identity.AddClaim(OpenIddictConstants.Claims.Name, name);
   
       // ✅ azp = client id (مهم للـ policy)
       if (!string.IsNullOrEmpty(request.ClientId))
           identity.AddClaim("azp", request.ClientId);
   
       // ✅ roles من Cookie Identity
       foreach (var role in httpContext.User.FindAll(ClaimTypes.Role).Select(x => x.Value))
           identity.AddClaim(OpenIddictConstants.Claims.Role, role);
   
       var principal = new ClaimsPrincipal(identity);
   
       // ✅ خذ scopes المطلوبة من الطلب
       principal.SetScopes(request.GetScopes());
   
       // ✅ لازم تحدد شو ينزل بالـ access_token
       principal.SetDestinations(claim => claim.Type switch
       {
           OpenIddictConstants.Claims.Subject => new[] { OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken },
           OpenIddictConstants.Claims.Name    => new[] { OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken },
           OpenIddictConstants.Claims.Role    => new[] { OpenIddictConstants.Destinations.AccessToken },
           "azp"                              => new[] { OpenIddictConstants.Destinations.AccessToken },
           "scope"                            => new[] { OpenIddictConstants.Destinations.AccessToken },
           _                                  => new[] { OpenIddictConstants.Destinations.AccessToken }
       });
   
       return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
   }).AllowAnonymous();
 */


/*
 * /connect/authorize?...&device_id=...&device_name=...&platform=...
 *
 * X-Device-Id: SAME_AS_device_id
   X-Device-Name: ...
   X-Platform:
   
 */
