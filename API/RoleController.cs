using IdentityServer.Interface;
using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Authorization;
using System.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.API
{
    [ApiController]
    [Route("api")]
    [Authorize(Policy = "SuperAdmin")]
    public class RoleController : ControllerBase
    {
        private readonly IRoleRep _roleRep;
        private readonly RoleManager<ApplicationRole> _roleManage;

        public RoleController(IRoleRep roleRep, RoleManager<ApplicationRole> roleManage)
        {
            _roleRep = roleRep;
            _roleManage = roleManage;
        }
        [HttpPost]
        [Route("AddRole")]
        [Produces("application/json")]
        public async Task<IActionResult> AddRole(ApplicationRoleView model)
        {

            if (ModelState.IsValid)
            {
                var result = await _roleRep.AddRole(model.Role);

                if (result.Status)
                {
                    return Ok(new
                    {
                        status = true,
                        description = result.Message
                    });
                }
                return Ok(new
                {
                    status = false,
                    description = result.Message
                });

            }
            return BadRequest();
        }

        [HttpPost]
        [Route("EditeRole")]
        [Produces("application/json")]
        public async Task<IActionResult> EditeRole(ApplicationRoleView model)
        {

            if (ModelState.IsValid)
            {
                var result = await _roleRep.EditeRole(model.id, model.Role);

                if (result.Status)
                {
                    return Ok(new
                    {
                        status = true,
                        result = result.Message
                    });
                }
                return Ok(new
                {
                    status = false,
                    result = result.Message
                });

            }
            return BadRequest();
        }

        [HttpPost]
        [Route("RemoveRole")]
        [Produces("application/json")]
        public async Task<IActionResult> RemoveRole(ApplicationRoleView model)
        {

            if (ModelState.IsValid)
            {
                var result = await _roleRep.RemoveRole(model.id);

                if (result.Status)
                {
                    return Ok(new
                    {
                        status = true,
                        result = result.Message
                    });
                }
                return Ok(new
                {
                    status = false,
                    result = result.Message
                });

            }
            return BadRequest();
        }

        [HttpGet]
        [Route("ListRole")]
        //[AllowAnonymous]
        public async Task<IActionResult> ListRole()
        {
            var Roles = await _roleManage.Roles.ToListAsync();
            Roles = Roles.Where(x => x.NormalizedName != "SUPERADMIN").ToList();
            return Ok(new
            {
                status = true,
                result = Roles,
            });

        }

        [HttpPost]
        [Route("GetRole")]
        public async Task<IActionResult> GetRole(RequestIDView requestId)
        {
            var Role = await _roleRep.GetRole(requestId.id.ToString());
            return Ok(new
            {
                status = true,
                result = Role
            });

        }
    }
}
