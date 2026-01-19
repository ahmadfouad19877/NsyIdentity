using IdentityServer.Interface;
using IdentityServer.Interface.ImageService;
using IdentityServer.Middleware;
using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.API
{
    [Route("api")]
    [ApiController]
    
    [Authorize]
    public class ProfileController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _manager;
        private readonly IImageService _imageService;
        private readonly IUserSessionRep _userSessionRep;


        public ProfileController(UserManager<ApplicationUser> manager,IImageService imageService,
            IUserSessionRep userSessionRep)
        {
            _manager = manager;
            _imageService = imageService;
            _userSessionRep = userSessionRep;
        }
        //EditeProfile
        [HttpPost]
        [Route("EditeProfile")]
        [Produces("application/json")]
        public async Task<IActionResult> EditeRole(ApplicationUserProfileView model)
        {
            if (ModelState.IsValid)
            {
                if (model.UserName != User.Identity.Name)
                {
                    return new ObjectResult("Not allowed") {StatusCode = 403};
                }
                var user = await _manager.FindByNameAsync(model.UserName);
                user.FName=model.FName!=null?model.FName:user.FName;
                user.LName=model.LName!=null?model.LName:user.LName;
                user.Identity=model.Identity!=null?model.Identity:user.Identity;
                user.Gender=model.Gender!=null?model.Gender:user.Gender;
                user.Birthday=model.Birthday!=null?model.Birthday:user.Birthday;
                user.Email=model.Email!=null?model.Email:user.Email;
                var result = await _manager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    return Ok(new
                    {
                        status = true,
                        result = "Updated Successfully",
                    });
                }
                return Ok(new
                {
                    status = false,
                    result = result.Errors
                });

            }
            return BadRequest();
        }
        //EditeImageProfile
        [HttpPost]
        [Route("EditeImageProfile")]
        [Produces("application/json")]
        public async Task<IActionResult> EditeImageProfile(ImageProfileView model)
        {
            if (ModelState.IsValid)
            {
                //https://alsultan.b-cdn.net/Profile-638805748769833860.webp
                //https://alsultan.b-cdn.net/Profile-638805748769833860.webp
                var user = await _manager.FindByNameAsync(User.Identity.Name);
                if (string.IsNullOrEmpty(user.Image))
                {
                    var image = await _imageService.UploadImageAsync(model.Image);
                    if (IsValidBunnyUrl(image))
                    {
                        user.Image=image;
                        await _manager.UpdateAsync(user);
                        return Ok(new
                        {
                            status = true,
                            result = image,
                        });
                        
                    }
                    return Ok(new
                    {
                        status = false,
                        result = image,
                    });
                    
                }
                else
                {
                    try
                    {
                        await _imageService.DeleteImageAsync(user.Image);
                    }
                    catch (Exception ex)
                    {
                        // سجل الخطأ أو تجاهله
                        Console.WriteLine($"خطأ في حذف الصورة: {ex.Message}");
                        // أو _logger.LogWarning(ex, "فشل حذف الصورة");
                    }
                    var image = await _imageService.UploadImageAsync(model.Image);
                    if (IsValidBunnyUrl(image))
                    {
                        user.Image=image;
                        await _manager.UpdateAsync(user);
                        return Ok(new
                        {
                            status = true,
                            result = image,
                        });
                        
                    }
                    return Ok(new
                    {
                        status = false,
                        result = image,
                    });
                }
            }
            return BadRequest();
        }
        //Profile
        [HttpGet]
        [Route("Profile")]
        [Produces("application/json")]
        public async Task<IActionResult> Profile()
        {
            var user = await _manager.FindByNameAsync(User.Identity.Name);
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
      
        
        //IsValidBunnyUrl For Check Image URL
        public static bool IsValidBunnyUrl(string? url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return false;

            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri))
                return false;

            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                return false;

            // السماح بـ bunny.net و b-cdn.net
            if (!(
                    uri.Host.EndsWith("bunny.net", StringComparison.OrdinalIgnoreCase) ||
                    uri.Host.EndsWith("b-cdn.net", StringComparison.OrdinalIgnoreCase)
                ))
                return false;

            return true;
        }
        
        //GetUserByUserName
        [HttpPost]
        [Route("GetUserByUserName")]
        [Produces("application/json")]
        [Authorize(Policy = "SuperAdmin")]
        public async Task<IActionResult> GetUserByID(ApplicationUserNameView model)
        {
            var user = await _manager.FindByNameAsync(model.UserName);
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
        
        
    }
}

