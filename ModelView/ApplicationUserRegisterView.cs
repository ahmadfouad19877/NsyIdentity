using System;
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ModelView
{
    public class ApplicationUserRegisterView
    {
        public ApplicationUserRegisterView()
        {
        }
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }


    }
}

