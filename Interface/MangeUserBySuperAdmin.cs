using IdentityServer.Models;
using IdentityServer.ModelView;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Interface;

public class MangeUserBySuperAdmin:IMangeUserBySuperAdmin
{
    
    private readonly UserManager<ApplicationUser> _manager;
    private readonly IProtectText _protectText;
    private readonly string _SultanUrfaAdmin;
    // ReSharper disable once InconsistentNaming
    private readonly string _SultanUrfaCalculate;
    private readonly string _SultanUrfaONS;
    private readonly string _SultanApp;
    private readonly string _esenler1Calculate;
    private readonly string _esenler2Calculate;
    private readonly string _rawiCalculate;

    public MangeUserBySuperAdmin(UserManager<ApplicationUser> manager,IProtectText protectText)
    {
        _SultanUrfaAdmin = "LeEKY1vT6EbDLznXy0uhoyirFu2rpPBW";
        _SultanUrfaCalculate = "4wwJr7Si5SwmoEsZG5BLSBZZPa5hVGsF";
        _SultanUrfaONS = "Pwoi80qIndoMXGlILtHOjf2rYqWJ2hHg";
        _SultanApp = "oOhh1JrJqfDWCwTvBipLoHUJezdd6IC2";
        _esenler1Calculate = "4ZQEAjuGRNKXzPZFHNIggRCp9tWXAagt";
        _esenler2Calculate = "lZG1fDuHd5FK9er6Qv4FIcRGnZxXRrbH";
        _rawiCalculate = "BH6Ds46HvIynHzHDAvXcsF1HL6SqB4JM";
        _manager = manager;
        _protectText = protectText;
    }

    public async Task<IdentityResult> RegisterNewUser(ApplicationUserRegisterView UserRegisterView)
    {
       
        var NewUser = new ApplicationUser
        {
            UserName = UserRegisterView.UserName,
            PhoneNumber=UserRegisterView.UserName,
            PhoneNumberConfirmed = true
        };
        var result = await _manager.CreateAsync(NewUser, UserRegisterView.Password);
        return result;
    }

    public async Task<IdentityResult> AddNewAdmin(ApplicationAdminUserView UserRegisterView)
    {
        var NewUser = new ApplicationUser
        {
            UserName = UserRegisterView.UserName,
            PhoneNumber=UserRegisterView.UserName,
            PhoneNumberConfirmed = true
        };
        
        var result = await _manager.CreateAsync(NewUser, UserRegisterView.Password);
        return result;
    }

    public async Task<IdentityResult> EditeAdminSecrite(ApplicationEditeAdminSecrit model)
    {
        return IdentityResult.Success;
    }
}