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
    public class ClientIdController : ControllerBase
    {
        private readonly IClientIdRep _clientIdRep;

        public ClientIdController(IClientIdRep clientIdRep)
        {
            _clientIdRep = clientIdRep;
        }
        [HttpPost]
        [Route("AddClientId")]
        public async Task<IActionResult> AddClientId(ApplicationAddClientIdView model)
        {
            try
            {
                var data = await _clientIdRep.AddClient(model);
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
        [Route("EditeClientId")]
        public async Task<IActionResult> EditeClient(ApplicationAddClientIdView model)
        {
            try
            {
                var data = await _clientIdRep.EditeClient(model);
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
        [Route("GetClientId")]
        public async Task<IActionResult> GetClient(RequestIDView model)
        {
            try
            {
                var data = await _clientIdRep.GetClient(model.ClientID);
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
        [Route("DeleteClientId")]
        public async Task<IActionResult> DeleteClient(RequestIDView model)
        {
            try
            {
                var data = await _clientIdRep.DeleteClient(model.ClientID);
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
        
        [HttpGet]
        [Route("ListClientId")]
        public async Task<IActionResult> ListClient()
        {
            try
            {
                var data = await _clientIdRep.ListClient();
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
