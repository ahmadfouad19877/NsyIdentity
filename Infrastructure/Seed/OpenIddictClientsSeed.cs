using IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

public static class OpenIddictClientsSeed
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        Console.WriteLine("Seeding OpenIddict Clients...Local");
        using var scope = services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDb>();
        var app= await manager.FindByClientIdAsync("PostmanLocal");
        var client = await manager.GetClientIdAsync(app);
        
        Console.WriteLine(client);
        
        if (client is null)
        {
            
            await EnsureClient(manager,
                clientId: "PostmanLocal",
                displayName: "Postman Local",
                redirectUri: "https://localhost:7266/cb"
            );
            var user = await userManager.FindByNameAsync("superadmin");
            var allow = new ApplicationUserAllowedClient
            {
                UserId = user.Id,
                ClientId = "PostmanLocal",
                IsEnabled = true,
            };
            db.AllowedClients.Add(allow);
            await db.SaveChangesAsync();
        }

        
    }

    private static async Task EnsureClient(
        IOpenIddictApplicationManager manager,
        string clientId,
        string displayName,
        string redirectUri)
    {
        if (await manager.FindByClientIdAsync(clientId) is not null)
            return;

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = displayName,
            ClientType = ClientTypes.Public,

            RedirectUris = { new Uri(redirectUri) },

            Permissions =
            {
                // endpoints
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,

                // grant types
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,

                // response types
                OpenIddictConstants.Permissions.ResponseTypes.Code,

                // scopes
                OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Scopes.OfflineAccess, // ✅ مهم
                OpenIddictConstants.Permissions.Prefixes.Scope + "local_app_api"
            },

            Requirements =
            {
                Requirements.Features.ProofKeyForCodeExchange // PKCE
            }
        });
    }
}