using System;
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.ModelView
{
    public class ApplicationLoginView
    {
        public ApplicationLoginView()
        {
        }
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }
        
        public string ClientId { get; set; }
        
        public string Scope { get; set; }
        
        public string Divice { get; set; }
        
        public string DiviceID { get; set; }
        
        public string? UserAgent { get; set; }
        
        public string? IP { get; set; }
        
        
        
    }
}

