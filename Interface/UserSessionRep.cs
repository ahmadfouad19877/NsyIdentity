using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace IdentityServer.Interface;

public class UserSessionRep: IUserSessionRep
{
    private readonly UserManager<ApplicationUser> _manager;
    private readonly ApplicationDb _db;
    private readonly IOpenIddictTokenManager _tokenManager;

    public UserSessionRep(UserManager<ApplicationUser> manager,ApplicationDb db,IOpenIddictTokenManager tokenManager)
    {
        _manager = manager;
        _db = db;
        _tokenManager = tokenManager;

    }
    
    public async Task<IEnumerable<ApplicationUserSessions>> ListSessionForUser(string UserID)
    {
        return await _db.UserSessions.Where(x =>
                x.UserId == UserID &&
                x.IsActive &&
                !x.IsRevoked)
            .OrderByDescending(x => x.LastSeenAt)
            .ToListAsync();
    }

    public async Task<ApplicationUserSessions> SessionForDiviceID(string userId,
        string clientId,
        string deviceId)
    {
        return await _db.UserSessions.OrderBy(x=>x.CreatedAt).LastOrDefaultAsync(x =>
            x.UserId == userId &&
            x.ClientId == clientId &&
            x.DeviceId == deviceId &&
            x.IsActive &&
            !x.IsRevoked);
    }

    public async Task<(int revokedSessions, int revokedTokens)> RevokeByClientAsync(
        string userId,
        string clientId,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userId))
            throw new ArgumentException("UserId is required.", nameof(userId));
        if (string.IsNullOrWhiteSpace(clientId))
            throw new ArgumentException("ClientId is required.", nameof(clientId));

        var sessions = await _db.UserSessions
            .Where(x => x.UserId == userId
                        && x.ClientId == clientId
                        && x.IsActive
                        && !x.IsRevoked)
            .ToListAsync(ct);

        return await RevokeInternalAsync(sessions, ct);
    }

    public async Task<(int revokedSessions, int revokedTokens)> RevokeByDeviceAsync(
        string userId,
        string clientId,
        string deviceId,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userId))
            throw new ArgumentException("UserId is required.", nameof(userId));
        if (string.IsNullOrWhiteSpace(clientId))
            throw new ArgumentException("ClientId is required.", nameof(clientId));
        if (string.IsNullOrWhiteSpace(deviceId))
            throw new ArgumentException("DeviceId is required.", nameof(deviceId));

        var sessions = await _db.UserSessions
            .Where(x => x.UserId == userId
                        && x.ClientId == clientId
                        && x.DeviceId == deviceId
                        && x.IsActive
                        && !x.IsRevoked)
            .ToListAsync(ct);

        return await RevokeInternalAsync(sessions, ct);
    }

    public async Task<(int revokedSessions, int revokedTokens)> RevokeAllExceptAsync(
        string userId,
        string keepClientId,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userId))
            throw new ArgumentException("UserId is required.", nameof(userId));
        if (string.IsNullOrWhiteSpace(keepClientId))
            throw new ArgumentException("KeepClientId is required.", nameof(keepClientId));

        var sessions = await _db.UserSessions
            .Where(x => x.UserId == userId
                        && x.IsActive
                        && !x.IsRevoked
                        && !(x.ClientId == keepClientId))
            .ToListAsync(ct);

        return await RevokeInternalAsync(sessions, ct);
    }

    public async Task<(int revokedSessions, int revokedTokens)> RevokeAllForUserAsync(string userId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userId))
            throw new ArgumentException("UserId is required.", nameof(userId));

        var sessions = await _db.UserSessions
            .Where(x => x.UserId == userId
                        && x.IsActive
                        && !x.IsRevoked)
            .ToListAsync(ct);

        return await RevokeInternalAsync(sessions, ct);
    }

    private async Task<(int revokedSessions, int revokedTokens)> RevokeInternalAsync(
        List<ApplicationUserSessions> sessions,
        CancellationToken ct)
    {
        if (sessions.Count == 0)
            return (0, 0);

        var revokedTokens = 0;

        foreach (var s in sessions)
        {
            if (!string.IsNullOrWhiteSpace(s.TokenId))
            {
                var token = await _tokenManager.FindByIdAsync(s.TokenId, ct);
                if (token is not null)
                {
                    var ok = await _tokenManager.TryRevokeAsync(token, ct);
                    if (ok) revokedTokens++;
                }
            }
        }

        var now = DateTime.UtcNow;
        foreach (var s in sessions)
        {
            s.IsActive = false;
            s.IsRevoked = true;
            s.RevokedAt = now;
        }

        await _db.SaveChangesAsync(ct);

        return (sessions.Count, revokedTokens);
    }
}





