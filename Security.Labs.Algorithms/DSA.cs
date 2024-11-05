using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Security.Labs.Algorithms;

public class DSA
{
    private readonly DSACryptoServiceProvider _dsa = new();

    public void ExportKeys(string publicKeyPath, string privateKeyPath)
    {
        var publicKey = _dsa.ExportSubjectPublicKeyInfo();
        File.WriteAllBytes(publicKeyPath, publicKey);

        var privateKey = _dsa.ExportPkcs8PrivateKey();
        File.WriteAllBytes(privateKeyPath, privateKey);
    }

    public void ImportKeys( string publicKeyPath, string privateKeyPath)
    {
        var publicKey = File.ReadAllBytes(publicKeyPath);
        _dsa.ImportSubjectPublicKeyInfo(publicKey, out _);
        
        var privateKey = File.ReadAllBytes(privateKeyPath);
        _dsa.ImportPkcs8PrivateKey(privateKey, out _);
    }

    public string SignData(string data)
    {
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var signature = _dsa.SignData(dataBytes);

        return BytesToHex(signature);
    }

    public bool VerifySignature(string data, string signature)
    {
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var signatureBytes = HexToBytes(signature);

        return _dsa.VerifyData(dataBytes, signatureBytes);
    }

    private byte[] HexToBytes(string hexString)
    {
        var hexBytes = new byte[hexString.Length / 2];
        for (int i = 0; i < hexBytes.Length; i++)
        {
            hexBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
        }

        return hexBytes;
    }

    private string BytesToHex(byte[] data)
    {
        return BitConverter.ToString(data).Replace("-", string.Empty);
    }
}
