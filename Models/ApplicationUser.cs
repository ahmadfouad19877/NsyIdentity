using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Models
{
    public class ApplicationUser : IdentityUser
    {
        public ApplicationUser()
        {
        }
        public string? FName { get; set; }
        public string? LName { get; set; }
        public string? Identity { get; set; }
        
        public string Image { get; set; }=string.Empty;
        public Gender? Gender { get; set; }
        public string? Birthday { get; set; }
        
    }
}
public enum Gender
{
    Male,
    Female,
}
