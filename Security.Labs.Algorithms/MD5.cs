using System.Text;

namespace Security.Labs.Algorithms;

public sealed class MD5
{
    // Constants for MD5 transformation
    private static readonly uint[] S =
    [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];

    private static readonly uint[] K =
    [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ];

    // Initial MD5 hash values
    private static readonly uint[] InitialHashValues =
    [
        0x67452301, // A
        0xefcdab89, // B
        0x98badcfe, // C
        0x10325476  // D
    ];

    public static string ComputeHashForString(string input)
    {
        var inputBytes = Encoding.UTF8.GetBytes(input);
        var hashBytes = ComputeHash(inputBytes);
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }

    public static string ComputeHashForFile(string filePath)
    {
        var fileBytes = File.ReadAllBytes(filePath);
        var hashBytes = ComputeHash(fileBytes);
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
    }

    private static byte[] ComputeHash(byte[] input)
    {
        // Step 1: Pad the input
        byte[] paddedInput = PadInput(input);

        // Step 2: Initialize hash values
        uint[] hash = (uint[])InitialHashValues.Clone();

        // Step 3: Process each 512-bit chunk
        for (int i = 0; i < paddedInput.Length / 64; i++)
        {
            uint[] block = new uint[16];
            Buffer.BlockCopy(paddedInput, i * 64, block, 0, 64);

            Transform(hash, block);
        }

        // Step 4: Output the final hash
        return GetHashBytes(hash);
    }

    private static byte[] PadInput(byte[] input)
    {
        long bitLength = input.Length * 8;
        int paddingLength = (56 - (input.Length + 1) % 64) % 64;
        byte[] paddedInput = new byte[input.Length + 1 + paddingLength + 8];

        Buffer.BlockCopy(input, 0, paddedInput, 0, input.Length);
        paddedInput[input.Length] = 0x80;

        byte[] lengthBytes = BitConverter.GetBytes(bitLength);
        Buffer.BlockCopy(lengthBytes, 0, paddedInput, paddedInput.Length - 8, 8);

        return paddedInput;
    }

    private static void Transform(uint[] hash, uint[] block)
    {
        uint A = hash[0];
        uint B = hash[1];
        uint C = hash[2];
        uint D = hash[3];

        for (int i = 0; i < 64; i++)
        {
            uint F;
            int g;

            if (i < 16)
            {
                F = (B & C) | (~B & D);
                g = i;
            }
            else if (i < 32)
            {
                F = (D & B) | (~D & C);
                g = (5 * i + 1) % 16;
            }
            else if (i < 48)
            {
                F = B ^ C ^ D;
                g = (3 * i + 5) % 16;
            }
            else
            {
                F = C ^ (B | ~D);
                g = (7 * i) % 16;
            }

            F = F + A + K[i] + block[g];
            A = D;
            D = C;
            C = B;
            B += LeftRotate(F, S[i]);
        }

        hash[0] += A;
        hash[1] += B;
        hash[2] += C;
        hash[3] += D;
    }

    private static uint LeftRotate(uint x, uint n)
    {
        return (x << (int)n) | (x >> (32 - (int)n));
    }

    private static byte[] GetHashBytes(uint[] hash)
    {
        return hash.SelectMany(BitConverter.GetBytes).ToArray();
    }
}
