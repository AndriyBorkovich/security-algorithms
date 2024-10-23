using MD5Custom = System.Security.Cryptography.MD5; 
using System.Text;

namespace Security.Labs.Algorithms;

public static class HelperMethods
{
    public static byte[] GetHashedKey(byte[] key, int keyLengthInBytes)
    {
        var bytesHash = MD5Custom.HashData(key);

        if (keyLengthInBytes == 16)
        {
            bytesHash = bytesHash.Take(bytesHash.Length / 2).ToArray();
        }
        else if (keyLengthInBytes == 32)
        {
            bytesHash = [.. bytesHash, .. MD5Custom.HashData(key)];
        }

        return bytesHash;
    }

    public static byte[] StringToBytes(string str)
    {
        return Encoding.UTF8.GetBytes(str);
    }

    public static string BytesToString(byte[] bytes)
    {
        return Encoding.UTF8.GetString(bytes);
    }
}
