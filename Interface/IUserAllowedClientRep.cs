using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Interface;

public interface IUserAllowedClientRep
{
    Task<IdentityResult> AddUserToClient(ApplicationUserAllowedClientView allowedClient);
    
    Task<IdentityResult> UpdateUserToClient(ApplicationUserAllowedClientView allowedClient);
    
    Task<IdentityResult> UpdateUserAudiences(ApplicationUserAllowedAudiencesView allowedAudiences);
    
    Task<IdentityResult> DeleteUserToClient(Guid ID);
    
    Task<IdentityResult> DisableUser(Guid ID);
    
    Task<IdentityResult> EnableUser(Guid ID);
    
    Task<IdentityResult> DeleteAllUserClient(String UserID);
    
    Task<IEnumerable<ApplicationUserAllowedClient>> ListForUser(string UserID);
    
    Task<IEnumerable<ApplicationUser>> ListForClient(string ClientID);
}