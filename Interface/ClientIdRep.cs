using IdentityServerNSY.API.Dtos;
using IdentityServerNSY.Interface;
using IdentityServerNSY.Models;
using IdentityServerNSY.ModelView;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace IdentityServerNSY.Interface;

/// <summary>
/// مستودع إدارة عملاء OpenIddict
/// OpenIddict clients repository
/// </summary>
public class ClientIdRep : IClientIdRep
{
    private readonly IServiceScope _scope;
    private readonly IOpenIddictApplicationManager _manager;

    public ClientIdRep(IServiceProvider services, IOpenIddictApplicationManager manager)
    {
        _scope = services.CreateScope();
        _manager = manager;
    }

    /// <summary>
    /// إضافة Public Client
    /// Add public client
    /// </summary>
    public async Task<IdentityResult> AddClient(ApplicationClientIdView allowedClient)
    {
        try
        {
            await EnsurePublicClient(
                _manager,
                clientId: allowedClient.clientId,
                displayName: allowedClient.displayName,
                redirectUris: allowedClient.redirectUris,
                scop: allowedClient.Scop
            );

            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    /// <summary>
    /// إضافة Client خاص بالسيرفر / introspection
    /// Add confidential server/introspection client
    /// </summary>
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

    /// <summary>
    /// إضافة Machine-to-Machine Client
    /// Add machine-to-machine client
    /// </summary>
    public async Task<IdentityResult> AddMachineClient(ApplicationMachineClientIdView allowedClient)
    {
        try
        {
            await EnsureMachineToMachineClient(
                _manager,
                clientId: allowedClient.clientId,
                clientSecret: allowedClient.clientSecrit,
                displayName: allowedClient.DisplayName,
                scopes: allowedClient.Scopes,
                allowIntrospection: allowedClient.AllowIntrospection
            );

            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    /// <summary>
    /// تعديل Public Client
    /// Edit public client
    /// </summary>
    public async Task<IdentityResult> EditeClient(ApplicationClientIdView allowedClient)
    {
        try
        {
            var client = await _manager.FindByClientIdAsync(allowedClient.clientId);
            if (client == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "404",
                    Description = "Client not found"
                });
            }

            var descriptor = new OpenIddictApplicationDescriptor();

            // تعبئة القيم الحالية أولاً
            // Populate current values first
            await _manager.PopulateAsync(descriptor, client);

            // تحديث الاسم الظاهر
            // Update display name
            descriptor.DisplayName = allowedClient.displayName;

            // تنظيف redirect URIs ثم إعادة بنائها
            // Clear redirect URIs and rebuild them
            descriptor.RedirectUris.Clear();

            foreach (var uri in allowedClient.redirectUris.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                descriptor.RedirectUris.Add(new Uri(uri));
            }

            // حذف كل السكوبات القديمة ثم إعادة إضافة المطلوب
            // Remove old scope permissions then add the requested one
            var scopePermissions = descriptor.Permissions
                .Where(p => p.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.OrdinalIgnoreCase))
                .ToList();

            foreach (var permission in scopePermissions)
            {
                descriptor.Permissions.Remove(permission);
            }

            // الإبقاء على profile دائماً
            // Always keep profile
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);

            if (!string.IsNullOrWhiteSpace(allowedClient.Scop))
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + allowedClient.Scop.Trim());
            }

            await _manager.UpdateAsync(client, descriptor);

            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    /// <summary>
    /// حذف Client
    /// Delete client
    /// </summary>
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

    /// <summary>
    /// جلب Client واحد
    /// Get single client
    /// </summary>
    public async Task<OpenIdClientDto?> GetClient(string clientId)
    {
        var app = await _manager.FindByClientIdAsync(clientId);
        if (app == null)
            return null;

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

    /// <summary>
    /// جلب كل الـ Clients
    /// List all clients
    /// </summary>
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

    /// <summary>
    /// جلب العملاء الذين لديهم introspection
    /// Get clients with introspection permission
    /// </summary>
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

    /// <summary>
    /// جلب العملاء الذين ليس لديهم introspection
    /// Get clients without introspection permission
    /// </summary>
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

    /// <summary>
    /// إنشاء أو تحديث Public Client
    /// Create or update public client
    /// </summary>
    private static async Task EnsurePublicClient(
        IOpenIddictApplicationManager manager,
        string clientId,
        string? displayName,
        List<string> redirectUris,
        string? scop)
    {
        var existing = await manager.FindByClientIdAsync(clientId);
        OpenIddictApplicationDescriptor descriptor;

        if (existing is null)
        {
            descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                DisplayName = displayName,
                ClientType = OpenIddictConstants.ClientTypes.Public
            };
        }
        else
        {
            descriptor = new OpenIddictApplicationDescriptor();
            await manager.PopulateAsync(descriptor, existing);

            descriptor.ClientId = clientId;
            descriptor.DisplayName = displayName;
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Public;
        }

        // تنظيف وإعادة بناء الصلاحيات
        // Clear and rebuild permissions
        descriptor.Permissions.Clear();

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.EndSession);

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.RefreshToken);

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);

        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);

        if (!string.IsNullOrWhiteSpace(scop))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scop.Trim());
        }

        // تنظيف وإعادة بناء المتطلبات
        // Clear and rebuild requirements
        descriptor.Requirements.Clear();
        descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);

        // تنظيف وإعادة بناء redirect uris
        // Clear and rebuild redirect URIs
        descriptor.RedirectUris.Clear();

        foreach (var uri in redirectUris.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            descriptor.RedirectUris.Add(new Uri(uri));
        }

        if (existing is null)
        {
            await manager.CreateAsync(descriptor);
        }
        else
        {
            await manager.UpdateAsync(existing, descriptor);
        }
    }

    /// <summary>
    /// إنشاء Confidential Client خاص بالسيرفر أو introspection
    /// Create confidential server/introspection client
    /// </summary>
    private static async Task EnsureServiceClient(
        IOpenIddictApplicationManager manager,
        string clientId,
        string clientSecrit,
        string displayName)
    {
        var existing = await manager.FindByClientIdAsync(clientId);
        OpenIddictApplicationDescriptor descriptor;

        if (existing is null)
        {
            descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = clientSecrit,
                DisplayName = displayName,
                ClientType = OpenIddictConstants.ClientTypes.Confidential
            };
        }
        else
        {
            descriptor = new OpenIddictApplicationDescriptor();
            await manager.PopulateAsync(descriptor, existing);

            descriptor.ClientId = clientId;
            descriptor.ClientSecret = clientSecrit;
            descriptor.DisplayName = displayName;
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Confidential;
        }

        // تنظيف وإعادة بناء الصلاحيات
        // Clear and rebuild permissions
        descriptor.Permissions.Clear();
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);

        if (existing is null)
        {
            await manager.CreateAsync(descriptor);
        }
        else
        {
            await manager.UpdateAsync(existing, descriptor);
        }
    }

    /// <summary>
    /// إنشاء أو تحديث Machine-to-Machine Client
    /// Create or update machine-to-machine client
    /// </summary>
    private static async Task EnsureMachineToMachineClient(
        IOpenIddictApplicationManager manager,
        string clientId,
        string clientSecret,
        string? displayName,
        List<string>? scopes,
        bool allowIntrospection = false)
    {
        var existing = await manager.FindByClientIdAsync(clientId);
        OpenIddictApplicationDescriptor descriptor;

        if (existing is null)
        {
            descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                DisplayName = displayName,
                ClientType = OpenIddictConstants.ClientTypes.Confidential
            };
        }
        else
        {
            descriptor = new OpenIddictApplicationDescriptor();
            await manager.PopulateAsync(descriptor, existing);

            descriptor.ClientId = clientId;
            descriptor.ClientSecret = clientSecret;
            descriptor.DisplayName = displayName;
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Confidential;
        }

        // تنظيف الصلاحيات القديمة وبناؤها من جديد
        // Clear old permissions and rebuild them
        descriptor.Permissions.Clear();

        // هذا العميل يأخذ token فقط من token endpoint
        // This client gets tokens from the token endpoint
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);

        // نوع المنحة هو client_credentials
        // Grant type is client_credentials
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);

        // إضافة السكوبات المطلوبة
        // Add requested scopes
        if (scopes is not null)
        {
            foreach (var scope in scopes
                         .Where(x => !string.IsNullOrWhiteSpace(x))
                         .Select(x => x.Trim())
                         .Distinct(StringComparer.OrdinalIgnoreCase))
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
            }
        }

        // صلاحية introspection اختيارية
        // Introspection permission is optional
        if (allowIntrospection)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Introspection);
        }

        // هذا النوع لا يحتاج redirect uris
        // This type does not need redirect URIs
        descriptor.RedirectUris.Clear();

        // وهذا النوع لا يحتاج PKCE
        // This type does not need PKCE
        descriptor.Requirements.Clear();

        if (existing is null)
        {
            await manager.CreateAsync(descriptor);
        }
        else
        {
            await manager.UpdateAsync(existing, descriptor);
        }
    }
    public async Task<List<OpenIdClientDetailsDto>> ListPublicClients()
    {
        var result = new List<OpenIdClientDetailsDto>();

        await foreach (var app in _manager.ListAsync())
        {
            var dto = await BuildClientDetailsDto(app);

            var isPublicClient =
                string.Equals(dto.ClientType, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase) &&
                dto.RedirectUris.Any();

            if (!isPublicClient)
                continue;

            dto.AppType = "PublicClient";
            result.Add(dto);
        }

        return result;
    }
    public async Task<List<OpenIdClientDetailsDto>> ListServerClients()
    {
        var result = new List<OpenIdClientDetailsDto>();

        await foreach (var app in _manager.ListAsync())
        {
            var dto = await BuildClientDetailsDto(app);

            var permissions = await _manager.GetPermissionsAsync(app);

            var hasIntrospection = permissions.Contains(OpenIddictConstants.Permissions.Endpoints.Introspection);
            var hasClientCredentials = permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);

            var isServer =
                string.Equals(dto.ClientType, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase) &&
                hasIntrospection &&
                !hasClientCredentials;

            if (!isServer)
                continue;

            dto.AppType = "ServerClient";
            result.Add(dto);
        }

        return result;
    }
    public async Task<List<OpenIdClientDetailsDto>> ListMachineClients()
    {
        var result = new List<OpenIdClientDetailsDto>();

        await foreach (var app in _manager.ListAsync())
        {
            var dto = await BuildClientDetailsDto(app);

            var permissions = await _manager.GetPermissionsAsync(app);

            var hasTokenEndpoint = permissions.Contains(OpenIddictConstants.Permissions.Endpoints.Token);
            var hasClientCredentials = permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);

            var isMachineClient =
                string.Equals(dto.ClientType, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase) &&
                hasTokenEndpoint &&
                hasClientCredentials;

            if (!isMachineClient)
                continue;

            dto.AppType = "MachineClient";
            result.Add(dto);
        }

        return result;
    }
    
    private async Task<OpenIdClientDetailsDto> BuildClientDetailsDto(object app)
    {
        var clientId = await _manager.GetClientIdAsync(app);
        var displayName = await _manager.GetDisplayNameAsync(app);
        var clientType = await _manager.GetClientTypeAsync(app);

        var permissions = await _manager.GetPermissionsAsync(app);

        var scopes = permissions
            .Where(p => p.StartsWith(OpenIddictConstants.Permissions.Prefixes.Scope, StringComparison.OrdinalIgnoreCase))
            .Select(p => p.Substring(OpenIddictConstants.Permissions.Prefixes.Scope.Length))
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct()
            .ToList();

        var redirectUris = (await _manager.GetRedirectUrisAsync(app))
            .Select(x => x.ToString())
            .ToList();

        var allowIntrospection = permissions.Contains(OpenIddictConstants.Permissions.Endpoints.Introspection);

        var hasClientCredentials = permissions.Contains(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
        var hasTokenEndpoint = permissions.Contains(OpenIddictConstants.Permissions.Endpoints.Token);

        var isMachineClient = hasClientCredentials && hasTokenEndpoint;

        var isPublicClient =
            string.Equals(clientType, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase) &&
            redirectUris.Any();

        return new OpenIdClientDetailsDto
        {
            ClientId = clientId ?? string.Empty,
            DisplayName = displayName,
            ClientType = clientType,
            Scopes = scopes,
            RedirectUris = redirectUris,
            AllowIntrospection = allowIntrospection,
            IsMachineClient = isMachineClient,
            IsPublicClient = isPublicClient,
            CreatedAt = DateTimeOffset.UtcNow // أو null إذا ما عندك
        };
    }
}