using System;
using System.ComponentModel.DataAnnotations;

namespace IdentityServerNSY.ModelView
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

