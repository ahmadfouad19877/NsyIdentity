using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Interface;

public interface IClientAllowedAud
{
    Task<IdentityResult> AddClientToAudiences(ApplicationCientAllowedAudiencesView allowedClient);
    
    Task<IdentityResult> UpdateClientToAudiences(ApplicationCientAllowedAudiencesView allowedAudiences);
    
    Task<IdentityResult> DisableClientIDToAudiences(RequestIDView allowedClient,bool disableClient=false);
    
    
    Task<IEnumerable<ApplicationClientAllowedAudience>> ListForClient(string clientId);
}