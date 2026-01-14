using System;
using IdentityServer.Models;
using IdentityServer.ModelView;

namespace IdentityServer.Interface
{
    public interface IRoleRep
    {
        Task<StatuseModel<string>> CreateRole();
        Task<StatuseModel<string>> AddRole(string Name);
        Task<StatuseModel<string>> EditeRole(string roleid, string Name);
        Task<StatuseModel<string>> RemoveRole(string roleid);
        Task<ApplicationRole> GetRole(string roleid);

        Task<ApplicationUser> Test(string user1);
    }
}

