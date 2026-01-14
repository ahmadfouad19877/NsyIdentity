using System;
namespace IdentityServer.ModelView
{
    public class StatuseModel<T> where T : class
    {
        public StatuseModel()
        {
        }
        public T Message { get; set; }

        public bool Status { get; set; }
    }
}

