using IdentityServer.Interface;
using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace IdentityServerNSY.API
{
    [Route("api")]
    [ApiController]
    [Authorize]
    public class SessionController : ControllerBase
    {
        private readonly IUserSessionRep _userSessionRep;
        private readonly UserManager<ApplicationUser> _manager;

        public SessionController(IUserSessionRep userSessionRep,UserManager<ApplicationUser> manager)
        {
            _userSessionRep = userSessionRep;
            _manager = manager;
        }
        [HttpGet]
        [Route("ListSessionForUser")]
        public async Task<IActionResult> ListSessionForUser()
        {
            try
            {
                var user=await _manager.FindByNameAsync(User.Identity.Name);
                var data = await _userSessionRep.ListSessionForUser(user.Id);
                return StatusCode(200, new
                {
                    status = true,
                    data
                }); 
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        [HttpGet]
        [Route("SessionForDiviceID")]
        public async Task<IActionResult> ListClient()
        {
            try
            {
                var clientId = User.GetClaim(OpenIddictConstants.Claims.ClientId);
                var deviceId = HttpContext.Request.Headers["X-Device-Id"].FirstOrDefault();
                var user=await _manager.FindByNameAsync(User.Identity.Name);
                var data = await _userSessionRep.SessionForDiviceID(user!.Id,clientId!,deviceId!);
                return StatusCode(200, new
                {
                    status = true,
                    data
                }); 
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        
        [HttpPost]
        [Route("RevokeByClientAsync")]
        public async Task<IActionResult> RevokeByClientAsync(ClientSessionRequests.RevokeUserSessionsByClientRequest requestIdView)
        {
            try
            {
                var user=await _manager.FindByNameAsync(User.Identity.Name);
                var data = await _userSessionRep.RevokeByClientAsync(user.Id,requestIdView.ClientId);
                return StatusCode(200, new
                {
                    status = true,
                    data
                }); 
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        
        [HttpPost]
        [Route("RevokeByDeviceAsync")]
        public async Task<IActionResult> RevokeByDeviceAsync(ClientSessionRequests.RevokeUserSessionByDeviceRequest requestIdView)
        {
            try
            {
                var user=await _manager.FindByNameAsync(User.Identity.Name);
                var data = await _userSessionRep.RevokeByDeviceAsync(user.Id,requestIdView.ClientId,requestIdView.DeviceId);
                return StatusCode(200, new
                {
                    status = true,
                    data
                }); 
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        
        
        [HttpGet]
        [Route("RevokeAllForUserAsync")]
        public async Task<IActionResult> RevokeAllForUserAsync()
        {
            try
            {
                var user=await _manager.FindByNameAsync(User.Identity.Name);
                var data = await _userSessionRep.RevokeAllForUserAsync(user.Id);
                return StatusCode(200, new
                {
                    status = true,
                    data
                }); 
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

    }
}
