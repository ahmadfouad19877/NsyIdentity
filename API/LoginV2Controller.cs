using IdentityServer.Interface;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.API
{
    [ApiController]
    [Route("api/v{version:apiVersion}")]
    [ApiVersion("2.0")]
    [Authorize(AuthenticationSchemes = "SultanUrfaAdmin", Roles = "superAdmin,Admin")]
    public class LoginV2Controller : ControllerBase
    {
        /*private readonly IRefreshTokenRep _refreshTokenRep;
        public LoginV2Controller(IRefreshTokenRep refreshTokenRep)
        {
            _refreshTokenRep = refreshTokenRep;

        }
        [HttpPost]
        [Route("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(ApplicationLoginView model)
        {
            try
            {
                var userAgent = Request.Headers["User-Agent"].ToString();
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                model.UserAgent = userAgent;
                model.IP = ipAddress;
                var token = await _refreshTokenRep.SetRefreshToken(model);
                if (token["Status"].Equals((object)true))
                {
                    return Ok(new
                    {
                        status = true,
                        acesstoken=token["Token"],
                        role=token["Role"],
                        ExpiresIn=token["ExpiresIn"]
                        
                    });
                }
                return Ok(new
                {
                    status = false,
                    Message=token["Message"],
                });
                
            }
            catch (Exception ex)
            {
                return StatusCode(200, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        [HttpPost]
        [Route("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> refresh(ApplicationDiviceIDView model)
        {
            try
            {
                var token = await _refreshTokenRep.GetAcessFromRefreshToken(model);
                
                if (token["Status"].Equals((object)true))
                {
                    return Ok(new
                    {
                        status = true,
                        acesstoken=token["Token"],
                        role=token["Role"],
                        ExpiresIn=token["ExpiresIn"]
                        
                    });
                }
                return Ok(new
                {
                    status = false,
                    Message=token["Message"],
                });
            }
            catch (Exception ex)
            {
                return StatusCode(200, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
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
                return Ok(new
                {
                    status = false,
                    Message="No revoked",
                });
            }
            catch (Exception ex)
            {
                return StatusCode(200, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
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
                return StatusCode(200, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }*/
    }
}
