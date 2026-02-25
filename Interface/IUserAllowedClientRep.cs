using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Interface;

public interface IUserAllowedClientRep
{
    Task<IdentityResult> AddUserToClient(ApplicationUserAllowedClientView allowedClient);
    
    Task<IdentityResult> ActiveUserToClient(RequestIDView allowedClient,bool disableClient=false);
    
    Task<IEnumerable<ApplicationUserAllowedClient>> ListForClient(string clientId);
    
    Task<IEnumerable<ApplicationUserAllowedClient>> ListForUser(string UserID);
    
    
}