using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Interface;

public class UserAllowedClientRep:IUserAllowedClientRep
{
    private readonly UserManager<ApplicationUser> _manager;
    private readonly ApplicationDb _db;
    private readonly IUserSessionRep _userSessionRep;
    private readonly CancellationToken _ct;

    public UserAllowedClientRep(UserManager<ApplicationUser> manager,ApplicationDb db,IUserSessionRep userSessionRep,
        CancellationToken ct = default)
    {
        _manager = manager;
        _db = db;
        _userSessionRep = userSessionRep;
        _ct = ct;

    }
    public async Task<IdentityResult> AddUserToClient(ApplicationUserAllowedClientView allowedClient)
    {
        try
        {
            var user = await _manager.FindByIdAsync(allowedClient.UserId);
            if (user == null) return IdentityResult.Failed(new IdentityError
            {
                Code = "404",
                Description = "User not found"
            });
            var allow = new ApplicationUserAllowedClient
            {
                UserId = user.Id,
                ClientId = allowedClient.ClientId,
                IsEnabled = true,
            };
            _db.AllowedClients.Add(allow);
            await _db.SaveChangesAsync();
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IdentityResult> UpdateUserToClient(ApplicationUserAllowedClientView allowedClient)
    {
        try
        {
            var allow = await _db.AllowedClients.FindAsync(allowedClient.Id);
            if (allow == null) throw new ArgumentException("ID is Error.", nameof(allowedClient.Id));
            if(allow.ClientId == allowedClient.ClientId)throw new ArgumentException("OldClientId is Same New ClientID.", nameof(allowedClient.OldClientId));
            if(allow.ClientId != allowedClient.OldClientId) throw new ArgumentException("OldClientId is Not Correct.", nameof(allowedClient.OldClientId));
            var cou=await _db.AllowedClients
                .Where(x => x.UserId == allowedClient.UserId && x.ClientId == allowedClient.ClientId).CountAsync();
            if(cou!=0) throw new ArgumentException("This User is have this ClientID.", nameof(allowedClient.OldClientId));
            await _userSessionRep.RevokeAllExceptAsync(
                userId: allow.UserId,        // أو null إذا بدك تلغي لكل المستخدمين
                keepClientId: allowedClient.OldClientId);
            allow.ClientId = allowedClient.ClientId;
            await _db.SaveChangesAsync();
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IdentityResult> DeleteUserToClient(Guid ID)
    {
        try
        {
            var allow = await _db.AllowedClients.FindAsync(ID);
            if (allow == null) throw new ArgumentException("ID is Error.", nameof(ID));
            await _userSessionRep.RevokeAllExceptAsync(
                userId: allow.UserId,      // أو null إذا لكل المستخدمين
                keepClientId: allow.ClientId,ct:_ct);
            _db.AllowedClients.Remove(allow);
            await _db.SaveChangesAsync();
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IdentityResult> DisableUser(Guid ID)
    {
        try
        {
            var allow = await _db.AllowedClients.FindAsync(ID);
            if (allow == null) return IdentityResult.Failed(new IdentityError
            {
                Code = "404",
                Description = "Allow not found"
            });
            allow.IsEnabled = false;
            await _db.SaveChangesAsync();
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IdentityResult> EnableUser(Guid ID)
    {
        try
        {
            var allow = await _db.AllowedClients.FindAsync(ID);
            if (allow == null) return IdentityResult.Failed(new IdentityError
            {
                Code = "404",
                Description = "Allow not found"
            });
            allow.IsEnabled = true;
            await _db.SaveChangesAsync();
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IdentityResult> DeleteAllUserClient(string UserID)
    {
        try
        {
            var list = await _db.AllowedClients.Where(x => x.UserId == UserID).ToListAsync();
            _db.AllowedClients.RemoveRange(list);
            await _userSessionRep.RevokeAllForUserAsync(UserID,_ct);
            await _db.SaveChangesAsync();
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IEnumerable<ApplicationUserAllowedClient>> ListForUser(string UserID)
    {
        return await _db.AllowedClients.Where(x => x.UserId == UserID&&x.IsEnabled).ToListAsync();
    }

    public async Task<IEnumerable<ApplicationUser>> ListForClient(string ClientID)
    {
        var users = await _db.AllowedClients
            .Where(x => x.ClientId == ClientID)
            .Select(x => x.User)   // Navigation Property
            .Distinct()
            .ToListAsync();

        return users;
    }
    
}