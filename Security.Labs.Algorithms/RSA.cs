using System.Security.Cryptography;
using System.Diagnostics;

namespace Security.Labs.Algorithms;

public class RSA
{
    public void GeneteKeyPair(string publicKeyPath, string privateKeyPath)
    {
        using var rsa = new RSACryptoServiceProvider(2048);

        var publicKey = rsa.ExportRSAPublicKey();
        var privateKey = rsa.ExportRSAPrivateKey();

        File.WriteAllBytes(publicKeyPath, publicKey);
        File.WriteAllBytes(privateKeyPath, privateKey);
    }

    public byte[] Encrypt(byte[] dataToEncrypt, byte[] publicKey)
    {
        using var rsa = new RSACryptoServiceProvider(2048);
        rsa.ImportRSAPublicKey(publicKey, out _);
        var encryptedData = rsa.Encrypt(dataToEncrypt, true);

        return encryptedData;
    }

    public byte[] Decrypt(byte[] dataToDecrypt, byte[] privateKey)
    {
        using var rsa = new RSACryptoServiceProvider(2048);
        rsa.ImportRSAPrivateKey(privateKey, out _);
        var decryptedData = rsa.Decrypt(dataToDecrypt, true);
        
        return decryptedData;
    }

    public int EncryptFile(string filePath, string publicKeyPath, string encodedPath)
    {
        var timer = new Stopwatch();

        var data = File.ReadAllBytes(filePath);
        var publicKey = File.ReadAllBytes(publicKeyPath);

        timer.Start();
        var encodedData = Encrypt(data, publicKey);
        timer.Stop();

        File.WriteAllBytes(encodedPath, encodedData);
        var timeTaken = timer.Elapsed;

        return timeTaken.Milliseconds;
    }

    public int DecryptFile(string filePath, string privateKeyPath, string decodedPath)
    {
        var timer = new Stopwatch();

        var data = File.ReadAllBytes(filePath);
        var privateKey = File.ReadAllBytes(privateKeyPath);

        timer.Start();
        var decodedData = Decrypt(data, privateKey);
        timer.Stop();
        File.WriteAllBytes(decodedPath, decodedData);
        var timeTaken = timer.Elapsed;

        return timeTaken.Milliseconds;
    }
}
