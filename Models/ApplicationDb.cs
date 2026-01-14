using System;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Models
{
    public class ApplicationDb : IdentityDbContext<ApplicationUser, ApplicationRole, string>
    {
        public ApplicationDb(DbContextOptions<ApplicationDb> options) : base(options) { }
        
        public DbSet<ApplicationUserAllowedClient> AllowedClients { get; set; }
        public DbSet<ApplicationUserSessions> UserSessions { get; set; }
        

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // ✅ هذا اللي كان ناقصك: يضيف جداول OpenIddict للـ EF model
            builder.UseOpenIddict();
        }
    }
}

