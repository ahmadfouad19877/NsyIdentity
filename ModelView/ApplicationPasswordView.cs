using System;
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ModelView
{
    public class ApplicationPasswordView
    {
        public ApplicationPasswordView()
        {
        }
        [Required]
        public string OldPassword { get; set; }

        [Required]
        public string NewPassword { get; set; }

        [Required]
        public string ConfirmPassword { get; set; }
    }
}

