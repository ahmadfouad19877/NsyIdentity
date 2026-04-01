using IdentityServerNSY.Models;
using IdentityServerNSY.ModelView;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace IdentityServerNSY.Interface;

public class ClientIdRep : IClientIdRep
{
    private readonly IServiceScope _scope;
    private readonly IOpenIddictApplicationManager _manager;

    public ClientIdRep(IServiceProvider services, IOpenIddictApplicationManager manager)
    {
        _scope = services.CreateScope();
        _manager = manager;
    }

    public async Task<IdentityResult> AddClient(ApplicationClientIdView allowedClient)
    {
        try
        {
            await EnsurePublicClient(
                _manager,
                clientId: allowedClient.clientId,
                displayName: allowedClient.displayName,
                redirectUris: allowedClient.redirectUris,
                Scop: allowedClient.Scop
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
            await EnsureServiceClient(
                _manager,
                clientId: allowedClient.clientId,
                clientSecrit: allowedClient.clientSecrit,
                displayName: allowedClient.DisplayName
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
            var clientId = await _manager.FindByClientIdAsync(allowedClient.clientId);
            if (clientId == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "404",
                    Description = "Client not found"
                });
            }

            var descriptor = new OpenIddictApplicationDescriptor();
            await _manager.PopulateAsync(descriptor, clientId);

            descriptor.DisplayName = allowedClient.displayName;

            descriptor.RedirectUris.Clear();

            foreach (var uri in allowedClient.redirectUris)
            {
                if (!string.IsNullOrWhiteSpace(uri))
                {
                    descriptor.RedirectUris.Add(new Uri(uri));
                }
            }

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
            var dClientId = await _manager.FindByClientIdAsync(clientId);
            if (dClientId == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "404",
                    Description = "Client not found"
                });
            }

            await _manager.DeleteAsync(dClientId);

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
        var app = await _manager.FindByClientIdAsync(clientId);
        var client = await _manager.GetClientIdAsync(app);

        if (string.IsNullOrWhiteSpace(client))
            return null;

        var permissions = await _manager.GetPermissionsAsync(app);

        var scopes = permissions
            .Where(p => p.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.OrdinalIgnoreCase))
            .Select(p => p.Substring(OpenIddictConstants.Permissions.Prefixes.Scope.Length))
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

            var scopes = permissions
                .Where(p => p.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Substring(OpenIddictConstants.Permissions.Prefixes.Scope.Length))
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

    public async Task<List<string>> GetClientsWithIntrospectionAsync()
    {
        var result = new List<string>();

        await foreach (var app in _manager.ListAsync())
        {
            var permissions = await _manager.GetPermissionsAsync(app);

            if (permissions.Contains(OpenIddictConstants.Permissions.Endpoints.Introspection))
            {
                var clientId = await _manager.GetClientIdAsync(app);
                if (!string.IsNullOrWhiteSpace(clientId))
                    result.Add(clientId);
            }
        }

        return result;
    }

    public async Task<List<string>> GetClientsWithoutIntrospectionAsync()
    {
        var result = new List<string>();

        await foreach (var app in _manager.ListAsync())
        {
            var permissions = await _manager.GetPermissionsAsync(app);

            if (!permissions.Contains(OpenIddictConstants.Permissions.Endpoints.Introspection))
            {
                var clientId = await _manager.GetClientIdAsync(app);
                if (!string.IsNullOrWhiteSpace(clientId))
                    result.Add(clientId);
            }
        }

        return result;
    }

    private static async Task EnsurePublicClient(
        IOpenIddictApplicationManager manager,
        string clientId,
        string? displayName,
        List<string> redirectUris,
        string? Scop)
    {
        if (await manager.FindByClientIdAsync(clientId) is not null)
            return;

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = displayName,
            ClientType = OpenIddictConstants.ClientTypes.Public,

            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Prefixes.Scope + Scop
            },

            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
            }
        };

        foreach (var uri in redirectUris)
        {
            if (!string.IsNullOrWhiteSpace(uri))
            {
                descriptor.RedirectUris.Add(new Uri(uri));
            }
        }

        await manager.CreateAsync(descriptor);
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