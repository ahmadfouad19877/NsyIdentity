using IdentityServerNSY.Models;
using IdentityServerNSY.ModelView;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityServerNSY.Interface;

public class ClientAllowedAud: IClientAllowedAud
{
    private readonly UserManager<ApplicationUser> _manager;
    private readonly ApplicationDb _db;
    private readonly CancellationToken _ct;

    public ClientAllowedAud(UserManager<ApplicationUser> manager,ApplicationDb db,
        CancellationToken ct = default)
    {
        _manager = manager;
        _db = db;
        _ct = ct;

    }
    public async Task<IdentityResult> AddClientToAudiences(ApplicationCientAllowedAudiencesView allowedClient)
    {
        try
        {
            var ClientAllow=await _db.AllowedAudiences.FirstOrDefaultAsync(x=>x.ClientId==allowedClient.ClientId&&x.Audience==allowedClient.Audiences);

            if (ClientAllow != null)
            {
                throw new ArgumentException("this ClientID is Add Befoor.", nameof(allowedClient.ClientId));
            }
            var allow = new ApplicationClientAllowedAudience
            {
                ClientId = allowedClient.ClientId,
                IsActive = true,
                Audience = allowedClient.Audiences
            };
            _db.AllowedAudiences.Add(allow);
            await _db.SaveChangesAsync();
            return IdentityResult.Success;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IdentityResult> UpdateClientToAudiences(ApplicationCientAllowedAudiencesView allowedAudiences)
    {
        var allow = await _db.AllowedAudiences.FindAsync(allowedAudiences.Id);
        if (allow == null)
        {
            throw new ArgumentException("this ClientId is Not Add Befoor.", nameof(allowedAudiences.ClientId));
        }

        if (allowedAudiences.Audiences==null)
        {
            throw new ArgumentException("the  Audiences is Null.", nameof(allowedAudiences.Audiences));
        }
        allow.Audience = allowedAudiences.Audiences;
        _db.AllowedAudiences.Update(allow);
        await _db.SaveChangesAsync();
        return IdentityResult.Success;
    }
    

    public async Task<IdentityResult> DisableClientIDToAudiences(RequestIDView allowedClient,bool disableClient=false)
    {
        var allow = await _db.AllowedAudiences.FindAsync(allowedClient.id);
        if (allow == null)
        {
            throw new ArgumentException("this ClientId is Not Add Befoor.", nameof(allowedClient.id));
        }

        allow.IsActive = disableClient;
        _db.AllowedAudiences.Update(allow);
        await _db.SaveChangesAsync();
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> DeleteClientIDToAudiences(RequestIDView allowedClient, bool disableClient = false)
    {
        var allow = await _db.AllowedAudiences.FindAsync(allowedClient.id);
        if (allow == null)
        {
            throw new ArgumentException("this ClientId is Not Add Befoor.", nameof(allowedClient.id));
        }
        _db.AllowedAudiences.Remove(allow);
        await _db.SaveChangesAsync();
        return IdentityResult.Success;
    }

    public async Task<IEnumerable<ApplicationClientAllowedAudience>> ListForClient(string clientId)
    {
        return await _db.AllowedAudiences.OrderBy(x=>x.Audience).Where(x=>x.ClientId==clientId).ToListAsync();
    }
}