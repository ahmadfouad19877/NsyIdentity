using System;
using System.ComponentModel.DataAnnotations;

namespace IdentityServerNSY.ModelView
{
    public class ApplicationRoleView
    {
        public ApplicationRoleView()
        {
        }
        public string? id { get; set; }
        [Required]
        public string Role { get; set; }
    }
}

