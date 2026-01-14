namespace IdentityServer.Interface.ImageService;

public interface IImageService
{
    Task<string> UploadImageAsync(IFormFile file);
    
    //Task<string> UpdateImageAsync(IFormFile file,String URL);
    Task<string> DeleteImageAsync(String URL);
}