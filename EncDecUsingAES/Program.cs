// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;
using EncDecUsingAES;

Console.WriteLine("Hello, World!");

// Console.WriteLine($"{CryptoEngine.GetRandomKey()}");
// Console.WriteLine($"{CryptoEngine.GetRandomKeyWithRandomNumberGenerator()}");

// Generate 32-byte AES key
byte[] aesKey = new byte[32];
using (RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create())
{
    randomNumberGenerator.GetBytes(aesKey);
}

// Generate 16-byte AES IV
byte[] aesIV = new byte[16];
using (RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create())
{
    randomNumberGenerator.GetBytes(aesIV);
}

// Convert the byte arrays to base64 strings for easy storage
string aesKeyBase64 = Convert.ToBase64String(aesKey);
string aesIVBase64 = Convert.ToBase64String(aesIV);

Console.WriteLine("Generated AES Key (Base64):");
Console.WriteLine(aesKeyBase64);
Console.WriteLine("Generated AES IV (Base64):");
Console.WriteLine(aesIVBase64);

const string originalText = "Charchil";
string cipherText = CryptoEngine.Encrypt(originalText, aesKeyBase64, aesIVBase64);
string decryptedText = CryptoEngine.Decrypt(cipherText, aesKeyBase64, aesIVBase64);

Console.WriteLine($"Original : {originalText}");
Console.WriteLine($"Cipher : {cipherText}");
Console.WriteLine($"Decrypted : {decryptedText}");