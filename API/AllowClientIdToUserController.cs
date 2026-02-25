using IdentityServerNSY.Interface;
using IdentityServerNSY.ModelView;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerNSY.API
{
    [Route("api")]
    [ApiController]
    [Authorize(Policy = "SuperAdmin")]
    public class AllowClientIdToUserController : ControllerBase
    {
        private readonly IUserAllowedClientRep _clientIdRep;
        

        public AllowClientIdToUserController(IUserAllowedClientRep clientIdRep)
        {
            _clientIdRep = clientIdRep;
            
        }
        [HttpPost]
        [Route("AddUserToClient")]
        public async Task<IActionResult> AddClientId(ApplicationUserAllowedClientView model)
        {
            try
            {
                var data = await _clientIdRep.AddUserToClient(model);
                if (data.Succeeded)
                {
                    return StatusCode(200, new
                    {
                        status = true
                    });
                }
                return StatusCode(402, new
                {
                    status = false,
                    data.Errors
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
        [Route("DisableUserToClient")]
        public async Task<IActionResult> DisableUser(RequestIDView model)
        {
            try
            {
                var data = await _clientIdRep.ActiveUserToClient(model);
                if (data.Succeeded)
                {
                    return StatusCode(200, new
                    {
                        status = true
                    });
                }
                return StatusCode(402, new
                {
                    status = false,
                    data.Errors
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
        [Route("EnableUserToClient")]
        public async Task<IActionResult> EnableUser(RequestIDView model)
        {
            try
            {
                var data = await _clientIdRep.ActiveUserToClient(model,true);
                if (data.Succeeded)
                {
                    return StatusCode(200, new
                    {
                        status = true
                    });
                }
                return StatusCode(402, new
                {
                    status = false,
                    data.Errors
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
        [Route("ListForUser")]
        public async Task<IActionResult> ListForUser(RequestIDView model)
        {
            try
            {
                var data = await _clientIdRep.ListForUser(model.UserID);
                return StatusCode(200, new
                {
                    status = true,
                    data
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
        [Route("ListForClient")]
        public async Task<IActionResult> ListForClient(RequestIDView model)
        {
            try
            {
                var data = await _clientIdRep.ListForClient(model.ClientID);
                return StatusCode(200, new
                {
                    status = true,
                    data
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
