using System.Security.Cryptography;
using System.Text;
using Aes = System.Security.Cryptography.Aes;

namespace EncDecUsingAES;

public static class CryptoEngine
{
    public static string Encrypt(string rawText, string aesKey, string aesIV)
    {
        if (!string.IsNullOrEmpty(rawText))
        {
            using Aes aes = Aes.Create();
            aes.Key = Convert.FromBase64String(aesKey);
            aes.IV = Convert.FromBase64String(aesIV);
            byte[] encryptedBytes = EncryptStringToBytes_Aes(rawText, aes.Key, aes.IV);
            return Convert.ToBase64String(encryptedBytes);
        }
        else
        {
            return string.Empty;
        }
    }

    public static string Decrypt(string encryption, string aesKey, string aesIV)
    {
        if (!string.IsNullOrEmpty(encryption))
        {
            using Aes aes = Aes.Create();

            aes.Key = Convert.FromBase64String(aesKey);
            aes.IV = Convert.FromBase64String(aesIV);
            byte[] data = Convert.FromBase64String(encryption);
            return DecryptStringFromBytes_Aes(data, aes.Key, aes.IV);
        }
        else
        {
            return string.Empty;
        }
    }

    public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
    {
        if (plainText == null || plainText.Length <= 0) throw new ArgumentNullException("plainText");
        if (Key == null || Key.Length <= 0) throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0) throw new ArgumentNullException("IV");

        byte[] encrypted;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using MemoryStream msEncrypt = new();
            using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);
            using (StreamWriter swEncrypt = new(csEncrypt))
            {
                swEncrypt.Write(plainText);
            }

            encrypted = msEncrypt.ToArray();
        }

        return encrypted;
    }

    public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
    {
        if (cipherText == null || cipherText.Length <= 0) throw new ArgumentNullException("cipherText");
        if (Key == null || Key.Length <= 0) throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0) throw new ArgumentNullException("IV");

        string plaintext = null;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using MemoryStream msDecrypt = new(cipherText);
            using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
            using StreamReader srDecrypt = new(csDecrypt);
            plaintext = srDecrypt.ReadToEnd();
        }

        return plaintext;
    }

    [Obsolete]
    public static string GetRandomKey()
    {
        var token = new StringBuilder();

        //Prepare a 10-character random text
        using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
        {
            var data = new byte[4];
            for (int i = 0; i < 10; i++)
            {
                //filled with an array of random numbers
                rngCsp.GetBytes(data);
                //this is converted into a character from A to Z
                var randomchar = Convert.ToChar(
                                          //produce a random number 
                                          //between 0 and 25
                                          BitConverter.ToUInt32(data, 0) % 26
                                          //Convert.ToInt32('A')==65
                                          + 65
                                 );
                token.Append(randomchar);
            }
        }

        return token.ToString();
    }

    public static string GetRandomKeyWithRandomNumberGenerator()
    {
        var token = new StringBuilder();

        //Prepare a 10-character random text
        using (RandomNumberGenerator rngCsp = RandomNumberGenerator.Create())
        {
            var data = new byte[4];
            for (int i = 0; i < 10; i++)
            {
                //filled with an array of random numbers
                rngCsp.GetBytes(data);
                //this is converted into a character from A to Z
                var randomchar = Convert.ToChar(
                                          //produce a random number 
                                          //between 0 and 25
                                          BitConverter.ToUInt32(data, 0) % 26
                                          //Convert.ToInt32('A')==65
                                          + 65
                                 );
                token.Append(randomchar);
            }
        }

        return token.ToString();
    }
}
