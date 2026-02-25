using System.Collections;
using IdentityServerNSY.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServerNSY.Interface;

public interface IClientIdRep
{
    Task<IdentityResult> AddClient(ApplicationClientIdView allowedClient);
    
    Task<IdentityResult> AddServer(ApplicationServerClientIdView allowedClient);
    
    Task<IdentityResult> EditeClient(ApplicationClientIdView allowedClient);
    
    Task<IdentityResult> DeleteClient(string clientId);
    
    Task<OpenIdClientDto> GetClient(string clientId);
    
    Task<List<OpenIdClientDto>> ListClient();
}