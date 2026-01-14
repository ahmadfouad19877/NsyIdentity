
using IdentityServer.Interface;
using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerNSY.API
{
    [ApiController]
    [Route("api")]
    [ApiVersion("1.0")]
    [Authorize(AuthenticationSchemes = "SultanUrfaAdmin", Roles = "superAdmin,Admin")]
    public class LoginController : ControllerBase
    {
        /*public LoginController()
        {
            

        }
        //revok
        [HttpPost]
        [Route("revok")]
        public async Task<IActionResult> revok(RequestIDView model)
        {
            try
            {
                var token = await _refreshTokenRep.RevokRefreshToken(model.revok.Value);
                
                if (token)
                {
                    return Ok(new
                    {
                        status = true,
                        Message="Reok"
                        
                    });
                }
                return StatusCode(400,new
                {
                    status = false,
                    Message="No revoked",
                });
            }
            catch (Exception ex)
            {
                return StatusCode(400, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        //ListDiviceForUser
        [HttpPost]
        [Route("ListDiviceForUser")]
        public async Task<IActionResult> ListDiviceForUser(UsersModelView model)
        {
            try
            {
                var List = await _refreshTokenRep.ListDivice(model.UserName);
                
                return Ok(new
                {
                    status = true,
                    Message=List
                        
                });
            }
            catch (Exception ex)
            {
                return StatusCode(400, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        //DisableUser
        [HttpPost]
        [Route("DisableUser")]
        public async Task<IActionResult> DisableUser(UsersModelView model)
        {
            try
            {
                var result = await _refreshTokenRep.DiableUser(model.UserName);
                
                if (result["Status"].Equals((object)true))
                {
                    return Ok(new
                    {
                        status = true,
                        Message=result["Message"],
                        Time=result["Time"],
                        
                    });
                }
                return StatusCode(400,new
                {
                    status = false,
                    Message=result["Message"]
                        
                });
            }
            catch (Exception ex)
            {
                return StatusCode(400, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        //EnableUser
        [HttpPost]
        [Route("EnableUser")]
        public async Task<IActionResult> EnableUser(UsersModelView model)
        {
            try
            {
                var result = await _refreshTokenRep.EnableUser(model.UserName);
                
                if (result["Status"].Equals((object)true))
                {
                    return Ok(new
                    {
                        status = true,
                        Message=result["Message"]
                        
                    });
                }
                return StatusCode(400,new
                {
                    status = false,
                    Message=result["Message"]
                        
                });
            }
            catch (Exception ex)
            {
                return StatusCode(400, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }*/
    }
}
