using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace IdentityServer.Interface;

public class ClientIdRep: IClientIdRep
{
    private readonly IServiceScope _scope;
    private readonly IOpenIddictApplicationManager _manager;
    


    public ClientIdRep(IServiceProvider services,IOpenIddictApplicationManager manager)
    {
        _scope = services.CreateScope();
        _manager = manager;
        
    }
    public async Task<IdentityResult> AddClient(ApplicationClientIdView allowedClient)
    {
        try
        {
            await EnsurePublicClient(_manager,
                clientId: allowedClient.clientId,
                displayName: allowedClient.displayName,
                redirectUri: allowedClient.redirectUri,
                Scop:allowedClient.Scop
            );
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
        
    }

    public async Task<IdentityResult> AddServer(ApplicationServerClientIdView allowedClient)
    {
        try
        {
            await EnsureServiceClient(_manager,
                clientId: allowedClient.clientId,
                clientSecrit:allowedClient.clientSecrit,
                displayName:allowedClient.DisplayName
            );
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IdentityResult> EditeClient(ApplicationClientIdView allowedClient)
    {
        
        try
        {
            // 1) Find application by ClientId
            var clientId = await _manager.FindByClientIdAsync(allowedClient.clientId);
            if (clientId == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "404",
                    Description = "Client not found"
                });
            }

            // 2) Populate descriptor from existing app
            var descriptor = new OpenIddictApplicationDescriptor();
            await _manager.PopulateAsync(descriptor, clientId);

            // 3) Modify what you want
            descriptor.DisplayName = allowedClient.displayName;

            // Example: change permissions/scopes safely
            //descriptor.Permissions.Remove("scp:"+);
            //descriptor.Permissions.Add("scp:sultan_app_api");

            // Example: redirect uris
            descriptor.RedirectUris.Clear();
            descriptor.RedirectUris.Add(new Uri(allowedClient.redirectUri));

            // 4) Update
            await _manager.UpdateAsync(clientId, descriptor);
            
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IdentityResult> DeleteClient(string clientId)
    {
        try
        {
            // 1) Find application by ClientId
            var DclientId = await _manager.FindByClientIdAsync(clientId);
            if (DclientId == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "404",
                    Description = "Client not found"
                });
            }
            await _manager.DeleteAsync(DclientId);
            
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<OpenIdClientDto> GetClient(string clientId)
    {
        
        var app= await _manager.FindByClientIdAsync(clientId);
        var client = await _manager.GetClientIdAsync(app);
        if (string.IsNullOrWhiteSpace(client))
            return null;

        var permissions = await _manager.GetPermissionsAsync(app);

        // ✅ scopes are stored as permissions like: "scp:profile", "scp:email" ...
        var scopes = permissions
            .Where(p => p.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.OrdinalIgnoreCase))
            .Select(p => p.Substring(OpenIddictConstants.Permissions.Prefixes.Scope.Length)) // remove "scp:"
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct()
            .ToList();

        var redirectUris = (await _manager.GetRedirectUrisAsync(app))
            .Select(u => u.ToString())
            .ToList();

        return new OpenIdClientDto
        {
            ClientId = client,
            DisplayName = await _manager.GetDisplayNameAsync(app),
            Scopes = scopes,
            ReturnUrls = redirectUris
        };

    }

    public async Task<List<OpenIdClientDto>> ListClient()
    {
        var list = new List<OpenIdClientDto>();

        await foreach (var app in _manager.ListAsync())
        {
            var clientId = await _manager.GetClientIdAsync(app);
            if (string.IsNullOrWhiteSpace(clientId))
                continue;

            var permissions = await _manager.GetPermissionsAsync(app);

            // ✅ scopes are stored as permissions like: "scp:profile", "scp:email" ...
            var scopes = permissions
                .Where(p => p.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Substring(OpenIddictConstants.Permissions.Prefixes.Scope.Length)) // remove "scp:"
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct()
                .ToList();

            var redirectUris = (await _manager.GetRedirectUrisAsync(app))
                .Select(u => u.ToString())
                .ToList();

            list.Add(new OpenIdClientDto
            {
                ClientId = clientId,
                DisplayName = await _manager.GetDisplayNameAsync(app),
                Scopes = scopes,
                ReturnUrls = redirectUris
            });
        }

        return list;
    }

    private static async Task EnsurePublicClient(
        IOpenIddictApplicationManager manager,
        string clientId,
        string displayName,
        string redirectUri,
        string Scop)
    {
        if (await manager.FindByClientIdAsync(clientId) is not null)
            return;

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = displayName,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            RedirectUris = { new Uri(redirectUri) },

            Permissions =
            {
                // endpoints
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                //OpenIddictConstants.Permissions.Endpoints.Introspection,
                // grant types
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                // response types
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                // scopes
                OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Scopes.OfflineAccess, // ✅ مهم
                OpenIddictConstants.Permissions.Prefixes.Scope + Scop
            },

            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange // PKCE
            }
        });
    }
    
    private static async Task EnsureServiceClient(
        IOpenIddictApplicationManager manager,
        string clientId,
        string clientSecrit,
        string displayName)
    {
        if (await manager.FindByClientIdAsync(clientId) is not null)
            return;

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecrit,
            DisplayName = displayName,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Introspection,
            },
            
        });
    }
}