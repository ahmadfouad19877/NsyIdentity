using IdentityServer.Interface;
using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using OpenIddict.Abstractions;

namespace IdentityServerNSY.API
{
    [Route("api")]
    [ApiController]
    [Authorize(Policy = "SuperAdmin")]
    public class SessionAdminController : ControllerBase
    {
        private readonly IUserSessionRep _userSessionRep;
        private readonly UserManager<ApplicationUser> _manager;

        public SessionAdminController(IUserSessionRep userSessionRep,UserManager<ApplicationUser> manager)
        {
            _userSessionRep = userSessionRep;
            _manager = manager;
        }
        [HttpPost]
        [Route("ListSessionForUserByAdmin")]
        public async Task<IActionResult> ListSessionForUser(RequestIDView requestID)
        {
            try
            {
                var user=await _manager.FindByNameAsync(requestID.UserID!);
                if (user == null) 
                    return StatusCode(400, new
                    {
                        status = false,
                        Message="chekUserID"
                    });         
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
        [HttpPost]
        [Route("SessionForDiviceIDByAdmin")]
        public async Task<IActionResult> ListClient(RequestIDView requestID)
        {
            try
            {
                
                var user=await _manager.FindByNameAsync(requestID.UserID!);
                var data = await _userSessionRep.SessionForDiviceID(user!.Id,requestID.ClientID!,requestID.DiviceID!);
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
        [Route("RevokeByClientAsyncByAdmin")]
        public async Task<IActionResult> RevokeByClientAsync(ClientSessionRequests.RevokeUserSessionsByClientRequest requestIdView)
        {
            try
            {
                var user=await _manager.FindByNameAsync(requestIdView.UserId!);
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
        [Route("RevokeByDeviceAsyncByAdmin")]
        public async Task<IActionResult> RevokeByDeviceAsync(ClientSessionRequests.RevokeUserSessionByDeviceRequest requestIdView)
        {
            try
            {
                var user=await _manager.FindByNameAsync(requestIdView.UserId!);
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
        [Route("RevokeAllForUserAsyncByAdmin")]
        public async Task<IActionResult> RevokeAllForUserAsync(RequestIDView requestIDView)
        {
            try
            {
                var user=await _manager.FindByNameAsync(requestIDView.UserID!);
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
