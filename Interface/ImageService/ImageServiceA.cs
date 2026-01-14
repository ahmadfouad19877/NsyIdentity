using System.Net.Http.Headers;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;

namespace IdentityServer.Interface.ImageService;

public class ImageService:IImageService
{
    private readonly string storageZone = "alsultan";
    private readonly string accessKey = "fab81c11-2f3b-49c1-89b9869f9c9c-d753-41e0"; // استبدله بمفتاح Bunny الحقيقي
    private readonly string regionUrl = "https://sg.storage.bunnycdn.com";
    public async Task<string> UploadImageAsync(IFormFile file)
    {
        try
        {
            if (file == null || file.Length == 0)
                return "يرجى اختيار صورة";
            
            //string extension = Path.GetExtension(file.FileName);
            string newFileName = $"Profile-{DateTime.UtcNow.Ticks}.webp";
            string fullPath = $"users/{newFileName}";
            string uploadUrl = $"{regionUrl}/{storageZone}/{fullPath}";

            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("AccessKey", accessKey);

            using var fileStream = file.OpenReadStream();
            using var content = new StreamContent(fileStream);
            content.Headers.ContentType = new MediaTypeHeaderValue(file.ContentType);

            var response = await httpClient.PutAsync(uploadUrl, content);

            if (response.IsSuccessStatusCode)
            {
                
                string publicUrl = $"https://{storageZone}.b-cdn.net/{fullPath}";
                
                return publicUrl;
            }

            return response.StatusCode.ToString();
        }
        catch (Exception ex)
        {
            return ex.ToString();
        }
    }

    public async Task<string> UpdateImageAsync(IFormFile file,String URL)
    {
        try
        {
            if (string.IsNullOrEmpty(URL))
                return "❌ يجب تحديد اسم الصورة";
            
            Uri uri = new Uri(URL);
            string relativePath = uri.AbsolutePath.Trim('/');
            string uploadUrl = $"{regionUrl.TrimEnd('/')}/{storageZone}/{relativePath}";
            
            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("AccessKey", accessKey);

            using var fileStream = file.OpenReadStream();
            using var content = new StreamContent(fileStream);
            content.Headers.ContentType = new MediaTypeHeaderValue(file.ContentType);

            var response = await httpClient.PutAsync(uploadUrl, content);

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("REEEESSSS"+response.Content.ReadAsStringAsync().Result);
                string publicUrl = $"https://{storageZone}.b-cdn.net/{relativePath}";
                
                return publicUrl;
            }

            return response.StatusCode.ToString();
        }
        catch (Exception ex)
        {
            return ex.ToString();
        }
    }

    public async Task<string> DeleteImageAsync(string URL)
    {
        try
        {
            Uri uri = new Uri(URL);
            string relativePath = uri.AbsolutePath.Trim('/');

            string deleteUrl = $"{regionUrl.TrimEnd('/')}/{storageZone}/{relativePath}";

            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("AccessKey", accessKey);

            var request = new HttpRequestMessage(HttpMethod.Delete, deleteUrl);
            var response = await httpClient.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                return "✅ تم حذف الصورة بنجاح";
            }
            else
            {
                return $"❌ فشل الحذف - الكود: {response.StatusCode}";
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
}