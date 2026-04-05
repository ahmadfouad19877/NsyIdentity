using System.Collections;
using IdentityServerNSY.API.Dtos;
using IdentityServerNSY.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServerNSY.Interface;

/// <summary>
/// واجهة إدارة عملاء OpenIddict
/// OpenIddict clients repository interface
/// </summary>
public interface IClientIdRep
{
    /// <summary>
    /// إضافة Public Client
    /// Add public client
    /// </summary>
    Task<IdentityResult> AddClient(ApplicationClientIdView allowedClient);

    /// <summary>
    /// إضافة Confidential Client خاص بالسيرفر أو introspection
    /// Add confidential server/introspection client
    /// </summary>
    Task<IdentityResult> AddServer(ApplicationServerClientIdView allowedClient);

    /// <summary>
    /// إضافة Machine-to-Machine Client
    /// Add machine-to-machine client
    /// </summary>
    Task<IdentityResult> AddMachineClient(ApplicationMachineClientIdView allowedClient);

    /// <summary>
    /// تعديل Public Client
    /// Edit public client
    /// </summary>
    Task<IdentityResult> EditeClient(ApplicationClientIdView allowedClient);

    /// <summary>
    /// حذف Client
    /// Delete client
    /// </summary>
    Task<IdentityResult> DeleteClient(string clientId);

    /// <summary>
    /// جلب Client واحد
    /// Get single client
    /// </summary>
    Task<OpenIdClientDto?> GetClient(string clientId);

    /// <summary>
    /// جلب كل الـ Clients
    /// List all clients
    /// </summary>
    Task<List<OpenIdClientDto>> ListClient();

    /// <summary>
    /// جلب الـ Clients الذين لديهم صلاحية introspection
    /// Get clients with introspection permission
    /// </summary>
    Task<List<string>> GetClientsWithIntrospectionAsync();

    /// <summary>
    /// جلب الـ Clients الذين ليس لديهم صلاحية introspection
    /// Get clients without introspection permission
    /// </summary>
    Task<List<string>> GetClientsWithoutIntrospectionAsync();
    
    Task<List<OpenIdClientDetailsDto>> ListPublicClients();
    Task<List<OpenIdClientDetailsDto>> ListServerClients();
    Task<List<OpenIdClientDetailsDto>> ListMachineClients();
}