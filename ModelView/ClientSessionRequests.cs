namespace IdentityServer.ModelView;

public class ClientSessionRequests
{
    public sealed class RevokeUserSessionsByClientRequest
    {
        public string? UserId { get; set; } = default!;
        public string ClientId { get; set; } = default!;
    }

    public sealed class RevokeUserSessionByDeviceRequest
    {
        public string? UserId { get; set; } = default!;
        public string ClientId { get; set; } = default!;
        public string DeviceId { get; set; } = default!;
    }

    public sealed class RevokeAllExceptOneRequest
    {
        public string UserId { get; set; } = default!;
        public string KeepClientId { get; set; } = default!;
        public string KeepDeviceId { get; set; } = default!;
    }
    
    public sealed class RevokeAllExceptForUserRequest
    {
        public string? UserId { get; set; } = default!;
    }
}