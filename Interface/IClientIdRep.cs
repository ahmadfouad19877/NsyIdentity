using System.Collections;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Interface;

public interface IClientIdRep
{
    Task<IdentityResult> AddClient(ApplicationClientIdView allowedClient);
    
    Task<IdentityResult> AddServer(ApplicationServerClientIdView allowedClient);
    
    Task<IdentityResult> EditeClient(ApplicationClientIdView allowedClient);
    
    Task<IdentityResult> DeleteClient(string clientId);
    
    Task<OpenIdClientDto> GetClient(string clientId);
    
    Task<List<OpenIdClientDto>> ListClient();
}