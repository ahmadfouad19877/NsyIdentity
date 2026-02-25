namespace IdentityServerNSY.Interface;

public interface IProtectText
{
    Task<String> EncryptString(string text);
    Task<String> DecryptString(string cipherText);
}