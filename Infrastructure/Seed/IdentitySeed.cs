using IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

public static class IdentitySeed
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();

        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        // =========================
        // 1️⃣ Seed Roles
        // =========================
        string[] roles = { "SuperAdmin", "Admin" };

        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new ApplicationRole
                {
                    Name = role
                });
            }
        }

        // =========================
        // 2️⃣ Seed Super Admin
        // =========================
        var User = "superadmin";
        var superAdminPassword = "S@1112";

        var superAdmin = await userManager.FindByNameAsync(User);
        if (superAdmin == null)
        {
            superAdmin = new ApplicationUser
            {
                UserName = User,
                Email = "superadmin@admin.com",
                EmailConfirmed = true,
                PhoneNumberConfirmed = true,
                
            };

            var result = await userManager.CreateAsync(superAdmin, superAdminPassword);
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(superAdmin, "SuperAdmin");
            }
        }

        // =========================
        // 3️⃣ Seed Admin
        // =========================
        User = "admin";
        var adminPassword = "S@1112";

        var admin = await userManager.FindByNameAsync(User);

        if (admin == null)
        {
            admin = new ApplicationUser
            {
                UserName = User,
                Email = "admin@admin.com",
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(admin, adminPassword);
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(admin, "Admin");
            }
        }
    }
}
