using System.Text;
using IdentityServer.Interface;
using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace IdentityServer.API
{
    [Route("api")]
    [ApiController]
    [Authorize(Policy = "SuperAdmin")]
    public class MangeAdminBySuperAdminController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _manager;
        private readonly IMangeUserBySuperAdmin _mangeUserBySuperAdmin;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManage;
        private readonly IUserAllowedClientRep _allowedClient;
        private readonly IClientIdRep _clientId;
        private readonly IOpenIddictApplicationManager _managerClient;


        public MangeAdminBySuperAdminController(UserManager<ApplicationUser> manager, IConfiguration config, SignInManager<ApplicationUser> signInManager,
            IMangeUserBySuperAdmin mangeUserBySuperAdmin,RoleManager<ApplicationRole> roleManage,IUserAllowedClientRep allowedClient,
            IClientIdRep clientId,IOpenIddictApplicationManager managerClient)
        {
            _manager = manager;
            _configuration = config;
            _signInManager = signInManager;
            _mangeUserBySuperAdmin = mangeUserBySuperAdmin;
            _roleManage = roleManage;
            _allowedClient=allowedClient;
            _clientId = clientId;
            _managerClient = managerClient;
        }
        
        [HttpPost]
        [Route("AddAdmin")]
        public async Task<IActionResult> Register(ApplicationAdminUserView model)
        {
            try
            {
                
                var user = await _manager.FindByNameAsync(model.UserName);
                var role = await _roleManage.FindByNameAsync(model.RoleName);
                var client = await _clientId.GetClient(model.ClientID);
                if (user != null)
                {
                    return StatusCode(400, new
                    {
                        status = false,
                        result = "This User registered In  System"
                    });
                }
                if (role == null)
                {
                    return StatusCode(400, new
                    {
                        status = false,
                        result = "This role Not registered In  System"
                    });
                }
                if (client.ClientId != model.ClientID)
                {
                    return StatusCode(400, new
                    {
                        status = false,
                        result = "This ClientID Not registered In  System"
                    });
                }
                if (model.AllowedAudiences.Count == 0)
                {
                    return StatusCode(400, new
                    {
                        status = false,
                        result = "This AllowedAudiences Nedded In  System"
                    });
                }
                var result = await _mangeUserBySuperAdmin.AddNewAdmin(model);
                if (result.Succeeded)
                {
                    var UserAdded = await _manager.FindByNameAsync(model.UserName);
                    
                    var addRole=await _manager.AddToRoleAsync(UserAdded, model.RoleName);
                    if (!addRole.Succeeded)
                    {
                        await _manager.DeleteAsync(UserAdded);
                        throw new ArgumentException("Role Note Added", nameof(model.RoleName));
                    }
                    var clientapp = new ApplicationUserAllowedClientView
                    {
                        UserId = UserAdded.Id,
                        ClientId = model.ClientID,
                        AllowedAudiences = model.AllowedAudiences,
                        IsEnabled = true,
                    };
                    var addUserToClient = await _allowedClient.AddUserToClient(clientapp);
                    if (!addUserToClient.Succeeded)
                    {
                        await _manager.RemoveFromRoleAsync(UserAdded, model.RoleName);
                        await _manager.DeleteAsync(UserAdded);
                        throw new ArgumentException("AddUserToClient  Errore", nameof(model.RoleName));
                        
                    }
                    var token = await _manager.GeneratePasswordResetTokenAsync(UserAdded);

                    // ✅ Encode token to be URL-safe
                    var tokenEncoded = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                    // ✅ build link
                    // خليها من config مثل: https://identity.i-myapp.com
                    var baseUrl = $"{Request.Scheme}://{Request.Host}";

                    var link = $"{baseUrl}/account/set-password?uid={Uri.EscapeDataString(UserAdded.Id)}&t={Uri.EscapeDataString(tokenEncoded)}";

                    return StatusCode(200, new
                    {
                        status = true,
                        result = link
                    });
                }
                return StatusCode(500, new
                {
                    
                    status = false,
                    result = "Error"
                });
                
            }
            catch (Exception ex)
            {
                var user = await _manager.FindByNameAsync(model.UserName);
                await _manager.RemoveFromRoleAsync(user, model.RoleName);
                await _manager.DeleteAsync(user);
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        [HttpPost]
        [Route("EditeAdminRole")]
        public async Task<IActionResult> EditeAdminRole(ApplicationEditeRoleAdminView model)
        {
            try
            {
                var user = await _manager.FindByNameAsync(model.UserName);
                var role = await _roleManage.FindByNameAsync(model.RoleName);
                if (user == null)
                {
                    return StatusCode(400, new
                    {
                        status = false,
                        result = "Check UserName"
                    });
                }
                if (role == null)
                {
                    return StatusCode(400, new
                    {
                        status = false,
                        result = "This role Not registered In  System"
                    });
                }

                
                var result = await _manager.RemoveFromRoleAsync(user,model.RemoveRoleName);
                if (result.Succeeded)
                {
                    var addToRoleAsync = await _manager.AddToRoleAsync(user, model.RoleName);
                    if (!addToRoleAsync.Succeeded)
                    {
                        throw new ArgumentException("Role Note Added", nameof(model.RoleName));
                    }
                    return StatusCode(200, new
                    {
                        status = true,
                        result = user,
                        
                    });
                }
                return StatusCode(500, new
                {
                    status = false,
                    result = "Error"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        [HttpGet]
        [Route("ListUser")]
        public async Task<IActionResult> ListUser()
        {
            try
            {
                var users = await _manager.Users.ToListAsync();
                
                return StatusCode(200, new
                {
                    status = true,
                    result = users
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        [HttpPost]
        [Route("ListUserInRole")]
        public async Task<IActionResult> ListUserAdmin(ApplicationRoleView model)
        {
            try
            {
                var users = await _manager.GetUsersInRoleAsync(model.Role);
                
                return StatusCode(200, new
                {
                    status = true,
                    result = users
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        [HttpPost]
        [Route("ListUserInClientID")]
        public async Task<IActionResult> ListUserAdmin(RequestIDView model)
        {
            try
            {
                var users = await _allowedClient.ListForClient(model.ClientID);
                
                return StatusCode(200, new
                {
                    status = true,
                    result = users
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        
        [HttpPost]
        [Route("getUserRole")]
        public async Task<IActionResult> getUserRole(ApplicationAdminGetRoleView model)
        {
            try
            {
                var user = await _manager.FindByNameAsync(model.UserName);
                var role = await _manager.GetRolesAsync(user);
                
                return StatusCode(200, new
                {
                    status = true,
                    result = role
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        //GetUserByUserName
        [HttpPost]
        [Route("GetUserByUserName")]
        [Produces("application/json")] 
        public async Task<IActionResult> GetUserByID(ApplicationUserNameView model)
        {
            
            var user = await _manager.FindByNameAsync(model.UserName);
            if (user == null) return BadRequest(new
            {
                message = "Check UserName"
            });
            return Ok(new
            {
                status = true,
                result = new
                {
                    user.UserName,
                    user.FName,
                    user.LName,
                    user.Identity,
                    user.Gender,
                    user.Birthday,
                    user.Email,
                    user.Image,
                }
            });
        }
        [HttpPost]
        [Route("RestMyPasswordByAdmin")]
        [Produces("application/json")]
        public async Task<IActionResult> RestMyPassword(ApplicationUserNameView model)
        {
            var user = await _manager.FindByNameAsync(model.UserName);

            if (user == null) return BadRequest(new
            {
                message = "Check UserName"
            });
            
            var token = await _manager.GeneratePasswordResetTokenAsync(user);

            // ✅ Encode token to be URL-safe
            var tokenEncoded = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            // ✅ build link
            // خليها من config مثل: https://identity.i-myapp.com
            var baseUrl = $"{Request.Scheme}://{Request.Host}";

            var link = $"{baseUrl}/account/set-password?uid={Uri.EscapeDataString(user.Id)}&t={Uri.EscapeDataString(tokenEncoded)}";
            /*
             *Nedd to Sent Link To Email Or Telphone
             *
             *
             *
             */
            return Ok(new
            {
                status = true,
                link,
            });
        }
    }
}
