using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Interface;

public interface IUserSessionRep
{
    
    Task<IEnumerable<ApplicationUserSessions>> ListSessionForUser(String UserID);
    
    Task<ApplicationUserSessions> SessionForDiviceID(string userId,
        string clientId,
        string deviceId);
    
    Task<(int revokedSessions, int revokedTokens)> RevokeByClientAsync(
        string userId,
        string clientId,
        CancellationToken ct = default);

    Task<(int revokedSessions, int revokedTokens)> RevokeByDeviceAsync(
        string userId,
        string clientId,
        string deviceId,
        CancellationToken ct = default);

    Task<(int revokedSessions, int revokedTokens)> RevokeAllExceptAsync(
        string userId,
        string keepClientId,
        CancellationToken ct = default);
    
    Task<(int revokedSessions, int revokedTokens)> RevokeAllForUserAsync(
        string userId,
        CancellationToken ct = default);
}