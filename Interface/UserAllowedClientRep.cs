using IdentityServerNSY.Models;
using IdentityServerNSY.ModelView;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityServerNSY.Interface;

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
            var ClientAllow=await _db.AllowedClients.FirstOrDefaultAsync(x=>x.ClientId==allowedClient.ClientId&&x.UserId==allowedClient.UserID);

            if (ClientAllow != null)
            {
                throw new ArgumentException("this ClientID is Add Befoor.", nameof(allowedClient.ClientId));
            }
            var allow = new ApplicationUserAllowedClient
            {
                ClientId = allowedClient.ClientId,
                UserId =   allowedClient.UserID,
                IsActive = true,
                
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
    
    public async Task<IdentityResult> ActiveUserToClient(RequestIDView allowedClient,bool disableClient=false)
    {
        try
        {
            var ClientAllow=await _db.AllowedClients.FindAsync(allowedClient.id);

            if (ClientAllow == null)
            {
                throw new ArgumentException("this ClientID is Not Add Befoor.", nameof(allowedClient.id));
            }
            ClientAllow.IsActive=disableClient;
            _db.AllowedClients.Update(ClientAllow);
            await _db.SaveChangesAsync();
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IEnumerable<ApplicationUserAllowedClient>> ListForClient(string clientId)
    {
        return await _db.AllowedClients.Include(x=>x.User).OrderBy(x=>x.ClientId).Where(x=>x.ClientId==clientId).ToListAsync();
    }

    public async Task<IEnumerable<ApplicationUserAllowedClient>> ListForUser(string UserID)
    {
        return await _db.AllowedClients.Include(x=>x.User).OrderBy(x => x.ClientId).Where(x=>x.UserId==UserID).ToListAsync();
    }
}