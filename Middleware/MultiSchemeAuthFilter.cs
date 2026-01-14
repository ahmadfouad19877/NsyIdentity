using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace IdentityServer.Middleware;

public class MultiSchemeAuthFilter : IAsyncActionFilter
{
    private readonly IAuthenticationSchemeProvider _schemeProvider;

    public MultiSchemeAuthFilter(IAuthenticationSchemeProvider schemeProvider)
    {
        _schemeProvider = schemeProvider;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        try
        {
            var schemes = new[] {"SultanApp", "SultanUrfaAdmin", "SultanUrfaCalculate", "SultanUrfaONS", "esenler1Calculate", "esenler2Calculate"};
            foreach (var scheme in schemes)
            {
                var result = await context.HttpContext.AuthenticateAsync(scheme);
                Console.WriteLine($"Trying scheme: {scheme} => Authenticated? {result.Succeeded}");

                if (result.Succeeded && result.Principal != null)
                {
                    context.HttpContext.User = result.Principal;
                    await next(); // تابع التنفيذ
                    return;
                }
            }

            context.Result = new UnauthorizedResult();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            context.Result = new UnauthorizedResult();
        }

        
    }
}