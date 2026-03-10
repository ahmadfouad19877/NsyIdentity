using IdentityServerNSY.Models;
using IdentityServerNSY.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServerNSY.Interface;

public interface IClientAllowedAud
{
    Task<IdentityResult> AddClientToAudiences(ApplicationCientAllowedAudiencesView allowedClient);
    
    Task<IdentityResult> UpdateClientToAudiences(ApplicationCientAllowedAudiencesView allowedAudiences);
    
    Task<IdentityResult> DisableClientIDToAudiences(RequestIDView allowedClient,bool disableClient=false);
    
    
    Task<IdentityResult> DeleteClientIDToAudiences(RequestIDView allowedClient,bool disableClient=false);
    
    
    Task<IEnumerable<ApplicationClientAllowedAudience>> ListForClient(string clientId);
}