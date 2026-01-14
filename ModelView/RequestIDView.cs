using System;
namespace IdentityServer.ModelView
{
    public class RequestIDView
    {
        public RequestIDView()
        {
        }
        public Guid? id { get; set; }
        
        public int? revok { get; set; }
        
        public string? ClientID { get; set; }
        
        public string? DiviceID { get; set; }
        
        public string? UserID { get; set; }
    }
}

