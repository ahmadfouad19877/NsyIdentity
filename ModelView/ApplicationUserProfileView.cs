using System;
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ModelView
{
	public class ApplicationUserProfileView
	{
		public ApplicationUserProfileView()
		{
		}
		public string? UserName { get; set; }
		
        public string? FName { get; set; }

        public string? LName { get; set; }
        
        public string? Email { get; set; }

        public string? Identity { get; set; }
        
        public Gender? Gender { get; set; }

        public string? Birthday { get; set; }
    }
}

