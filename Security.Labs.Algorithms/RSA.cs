using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

namespace Security.Labs.Algorithms;

public class RSA
{
    public void GeneteKeyPair(string publicKeyPath, string privateKeyPath)
    {
        using RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);

        var publicKey = rsa.ExportRSAPublicKey();
        var privateKey = rsa.ExportRSAPrivateKey();

        File.WriteAllBytes(publicKeyPath, publicKey);
        File.WriteAllBytes(privateKeyPath, privateKey);
    }

    public byte[] Encrypt(byte[] dataToEncrypt, byte[] publicKey)
    {
        using RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
        rsa.ImportRSAPublicKey(publicKey, out int bytesRead);
        byte[] encryptedData;
        encryptedData = rsa.Encrypt(dataToEncrypt, true);
        return encryptedData;
    }

    public byte[] Decrypt(byte[] dataToDecrypt, byte[] privateKey)
    {
        using RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
        rsa.ImportRSAPrivateKey(privateKey, out int bytesRead);
        var decryptedData = rsa.Decrypt(dataToDecrypt, true);
        return decryptedData;
    }


    public void EncryptFile(string filePath, string publicKeyPath, string encodedPath)
    {
        var data = File.ReadAllBytes(filePath);
        var publicKey = File.ReadAllBytes(publicKeyPath);
        var encodedData = Encrypt(data, publicKey);
        File.WriteAllBytes(encodedPath, encodedData);
    }

    public int EncryptFileBenchmark(string filePath, string publicKeyPath, string encodedPath)
    {
        var timer = new Stopwatch();

        var data = File.ReadAllBytes(filePath);
        var publicKey = File.ReadAllBytes(publicKeyPath);

        timer.Start();
        var encodedData = Encrypt(data, publicKey);
        timer.Stop();
        File.WriteAllBytes(encodedPath, encodedData);
        TimeSpan timeTaken = timer.Elapsed;

        return timeTaken.Milliseconds;
    }

    public int DecryptFileBenchmark(string filePath, string privateKeyPath, string decodedPath)
    {
        var timer = new Stopwatch();

        var data = File.ReadAllBytes(filePath);
        var privateKey = File.ReadAllBytes(privateKeyPath);

        timer.Start();
        var decodedData = Decrypt(data, privateKey);
        timer.Stop();
        File.WriteAllBytes(decodedPath, decodedData);
        TimeSpan timeTaken = timer.Elapsed;

        return timeTaken.Milliseconds;
    }

    public void DecryptFile(string filePath, string privateKeyPath, string decodedPath)
    {
        var data = File.ReadAllBytes(filePath);
        var privateKey = File.ReadAllBytes(privateKeyPath);
        var decodedData = Decrypt(data, privateKey);
        File.WriteAllBytes(decodedPath, decodedData);
    }
}
