using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Authorization;
using System.Data;
using IdentityServer.Interface;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.API
{
    [ApiController]
    [Route("api")]
    public class RegisterController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _manager;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IMangeUserBySuperAdmin _mangeUserBySuperAdmin;
        private readonly IUserAllowedClientRep _allowedClient;


        public RegisterController(UserManager<ApplicationUser> manager, IConfiguration config, SignInManager<ApplicationUser> signInManager,
            IMangeUserBySuperAdmin mangeUserBySuperAdmin,IUserAllowedClientRep allowedClient)
        {
            _manager = manager;
            _configuration = config;
            _signInManager = signInManager;
            _mangeUserBySuperAdmin = mangeUserBySuperAdmin;
            _allowedClient = allowedClient;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register(ApplicationUserRegisterView model)
        {
            try
            {
                var user = await _manager.FindByNameAsync(model.UserName);
                if (user != null)
                {
                    return StatusCode(400, new
                    {
                        status = false,
                        result = "This User registered In  System"
                    });
                }
                
                var result = await _mangeUserBySuperAdmin.RegisterNewUser(model);
                if (result.Succeeded)
                {
                    var userAddedd=await _manager.FindByNameAsync(model.UserName);
                    await _manager.AddToRoleAsync(userAddedd, "User");
                    var clientapp = new ApplicationUserAllowedClientView
                    {
                        UserId = userAddedd.Id,
                        ClientId = "GApplication",
                        IsEnabled = true,
                    };
                    await _allowedClient.AddUserToClient(clientapp);
                    return StatusCode(200, new
                    {
                        status = true,
                        result = userAddedd
                    });
                    
                }
                return StatusCode(400, new
                {
                    status = false,
                    result = result.Errors
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

    }
}
