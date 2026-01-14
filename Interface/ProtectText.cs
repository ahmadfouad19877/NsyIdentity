using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace IdentityServer.Interface;

public class ProtectText:IProtectText
{
    private readonly string _appName;
    private readonly string _SecritKey;
    private readonly IDataProtectionProvider _dataProtectionProvider;

    public ProtectText()
    {
        _appName = "ALSultanApp";
        _SecritKey = "E546C8DF278CD5931069B522E695D4F2";
        _dataProtectionProvider = DataProtectionProvider.Create(_appName);
    }
    public async Task<string> Protect(string Text)
    {
        var protector = _dataProtectionProvider.CreateProtector(_SecritKey);
        return protector.Protect(Text);
    }

    public async Task<string> UnProtect(string ProtectText)
    {
        var protector = _dataProtectionProvider.CreateProtector(_SecritKey);
        Console.WriteLine(_SecritKey);
        Console.WriteLine(ProtectText);
        return protector.Unprotect(ProtectText);
    }

    public async Task<string> EncryptString(string encryptString)
    {
        byte[] clearBytes = Encoding.Unicode.GetBytes(encryptString);
        using(Aes encryptor = Aes.Create())
        {
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(_SecritKey, new byte[] {
                0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76
            });
            encryptor.Key = pdb.GetBytes(32);
            encryptor.IV = pdb.GetBytes(16);
            using(MemoryStream ms = new MemoryStream())
            {
                using(CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write)) {
                    cs.Write(clearBytes, 0, clearBytes.Length);
                    cs.Close();
                }
                encryptString = Convert.ToBase64String(ms.ToArray());
            }
        }
        return encryptString;
    }

    public async Task<string> DecryptString(string cipherText)
    {
        cipherText = cipherText.Replace(" ", "+");
        byte[] cipherBytes = Convert.FromBase64String(cipherText);
        using(Aes encryptor = Aes.Create())
        {
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(_SecritKey, new byte[] {
                0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76
            });
            encryptor.Key = pdb.GetBytes(32);
            encryptor.IV = pdb.GetBytes(16);
            using(MemoryStream ms = new MemoryStream())
            {
                using(CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write)) {
                    cs.Write(cipherBytes, 0, cipherBytes.Length);
                    cs.Close();
                }
                cipherText = Encoding.Unicode.GetString(ms.ToArray());
            }
        }
        return cipherText;

    }
}