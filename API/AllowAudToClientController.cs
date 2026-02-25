using IdentityServer.Interface;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerNSY.API
{
    [Route("api")]
    [ApiController]
    [Authorize(Policy = "SuperAdmin")]
    public class AllowAudToClientController : ControllerBase
    {
        private readonly IClientAllowedAud _clientAllowedAud;

        public AllowAudToClientController(IClientAllowedAud clientAllowedAud)
        {
            _clientAllowedAud = clientAllowedAud;
        }
        [HttpPost]
        [Route("AddAudToClient")]
        public async Task<IActionResult> AddClientId(ApplicationCientAllowedAudiencesView model)
        {
            try
            {
                var data = await _clientAllowedAud.AddClientToAudiences(model);
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
        [Route("UpdateAudToClient")]
        public async Task<IActionResult> UpdateAudToClient(ApplicationCientAllowedAudiencesView model)
        {
            try
            {
                var data = await _clientAllowedAud.UpdateClientToAudiences(model);
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
        [Route("DisableAudToClient")]
        public async Task<IActionResult> DisableUser(RequestIDView model)
        {
            try
            {
                var data = await _clientAllowedAud.DisableClientIDToAudiences(model);
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
        [Route("EnableAudToClient")]
        public async Task<IActionResult> EnableUser(RequestIDView model)
        {
            try
            {
                var data = await _clientAllowedAud.DisableClientIDToAudiences(model, true);
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
        [Route("ListAudForClient")]
        public async Task<IActionResult> ListForUser(RequestIDView model)
        {
            try
            {
                var data = await _clientAllowedAud.ListForClient(model.ClientID);
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
