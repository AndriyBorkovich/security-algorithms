using Security.Labs.Algorithms.Words;

namespace Security.Labs.Algorithms;

public class RC5
{
    private readonly LehmerGenerator _randomNumbersGenerator;
    private readonly int _wordSize;
    private readonly int _roundsCount;
    
    private int BytesPerWord(int w) => _wordSize / 8;

    public byte[] RandomBytesForIV;
    
    public RC5(int wordSize, int roundsCount, int keyLengthInBytes)
    {
        _wordSize = wordSize;
        _roundsCount = roundsCount;
        _randomNumbersGenerator = new LehmerGenerator(A: (long)Math.Pow(2, 5), C: 2, M: (long)(Math.Pow(2, 10) - 1), X0: 23, Count: keyLengthInBytes, OutputToFile: false);
    }

    private Word CreateWord(ulong value = 0)
    {
        if (_wordSize == 16)
        {
            return new Word16
            {
                WordValue = (ushort)value,
            };
        }

        if (_wordSize == 32)
        {
            return new Word32
            {
                WordValue = (uint)value,
            };
        }

        return new Word64
        {
            WordValue = value,
        };
    }

    private Word GetP()
    {
        ulong p = 0;
        if (_wordSize == 16) p = 0xB7E1;
        if (_wordSize == 32) p = 0xB7E15162;
        if (_wordSize == 64) p = 0xB7E151628AED2A6B;
        return CreateWord(p);
    }

    private Word GetQ()
    {
        ulong q = 0;
        if (_wordSize == 16) q = 0x9E37;
        if (_wordSize == 32) q = 0x9E3779B9;
        if (_wordSize == 64) q = 0x9E3779B97F4A7C15;
        return CreateWord(q);
    }

    private Word CreateFromBytes(byte[] bytes, int startFromIndex)
    {
        var word = CreateWord();
        word.CreateFromBytes(bytes, startFromIndex);

        return word;
    }

    private void EncodeBlock(byte[] inBytes, byte[] outBytes, int inStart, int outStart, Word[] s)
    {
        var a = CreateFromBytes(inBytes, inStart);
        var b = CreateFromBytes(inBytes, inStart + BytesPerWord(_wordSize));

        a.Add(s[0]);
        b.Add(s[1]);

        for (var i = 1; i < _roundsCount + 1; ++i)
        {
            a.Xor(b).CLS(b.ToInt32()).Add(s[2 * i]);
            b.Xor(a).CLS(a.ToInt32()).Add(s[2 * i + 1]);
        }

        a.ToBytes(outBytes, outStart);
        b.ToBytes(outBytes, outStart + BytesPerWord(_wordSize));
    }

    private void DecodeBlock(byte[] inBuf, byte[] outBuf, int inStart, int outStart, Word[] s)
    {
        var a = CreateFromBytes(inBuf, inStart);
        var b = CreateFromBytes(inBuf, inStart + BytesPerWord(_wordSize));

        for (var i = _roundsCount; i > 0; --i)
        {
            b = b.Sub(s[2 * i + 1]).CRS(a.ToInt32());
            b.Xor(a);
            a = a.Sub(s[2 * i]).CRS(b.ToInt32());
            a.Xor(b);
        }

        a.Sub(s[0]);
        b.Sub(s[1]);

        a.ToBytes(outBuf, outStart);
        b.ToBytes(outBuf, outStart + BytesPerWord(_wordSize));
    }

    private byte[] GeneratePadding(byte[] inBytes)
    {
        var paddingLength = BytesPerWord(_wordSize) * 2 - inBytes.Length % (BytesPerWord(_wordSize) * 2);

        var padding = new byte[paddingLength];

        for (int i = 0; i < padding.Length; ++i)
        {
            padding[i] = (byte)paddingLength;
        }

        return padding;
    }

    private byte[] GenerateRandomBytesForIV()
    {
        var ivParts = new List<byte>();

        foreach (var randomNumber in _randomNumbersGenerator.GenerateSequence(out _, out _))
        {
            var bytes = BitConverter.GetBytes(randomNumber);

            ivParts.AddRange(bytes);

            if (ivParts.Count >= BytesPerWord(_wordSize) * 2)
            {
                break;
            }
        }

        var result = ivParts.Take(BytesPerWord(_wordSize) * 2).ToArray();
        RandomBytesForIV = new byte[result.Length];
        Array.Copy(result, RandomBytesForIV, result.Length);

        return result;
    }

    private Word[] GetExtendedKeyTable(byte[] key)
    {
        var keysWordArrLength = key.Length % BytesPerWord(_wordSize) > 0
            ? key.Length / BytesPerWord(_wordSize) + 1
            : key.Length / BytesPerWord(_wordSize);

        var L = new Word[keysWordArrLength];

        for (int i = 0; i < L.Length; i++)
        {
            L[i] = CreateWord();
        }

        for (var i = key.Length - 1; i >= 0; i--)
        {
            L[i / BytesPerWord(_wordSize)].CLS(8).Add(key[i]);
        }

        var S = new Word[2 * (_roundsCount + 1)];
        S[0] = GetP();
        var q = GetQ();

        for (var i = 1; i < S.Length; i++)
        {
            S[i] = S[i - 1].Clone();
            S[i].Add(q);
        }

        var x = CreateWord();
        var y = CreateWord();
        var n = 3 * Math.Max(S.Length, L.Length);

        for (int k = 0, i = 0, j = 0; k < n; ++k)
        {
            S[i].Add(x).Add(y).CLS(3);
            x = S[i].Clone();

            L[j].Add(x).Add(y).CLS(x.ToInt32() + y.ToInt32());
            y = L[j].Clone();

            i = (i + 1) % S.Length;
            j = (j + 1) % L.Length;
        }

        return S;
    }

    private void Xor(byte[] array, byte[] xorArray, int inStartIndex, int xorStartIndex, int length)
    {
        for (int i = 0; i < length; ++i)
        {
            array[i + inStartIndex] ^= xorArray[i + xorStartIndex];
        }
    }

    public byte[] Encode(byte[] input, byte[] key)
    {
        var paddedInputData = input.Concat(GeneratePadding(input)).ToArray();
        var blockSizeInBytes = BytesPerWord(_wordSize) * 2;

        var extendedKeyTable = GetExtendedKeyTable(key);
        var initializationVector = GenerateRandomBytesForIV().Take(blockSizeInBytes).ToArray();
        var encryptedData = new byte[initializationVector.Length + paddedInputData.Length];

        EncodeBlock(initializationVector, encryptedData, 0, 0, extendedKeyTable);

        for (int i = 0; i < paddedInputData.Length; i += blockSizeInBytes)
        {
            var cn = new byte[blockSizeInBytes];
            Array.Copy(paddedInputData, i, cn, 0, cn.Length);

            Xor(cn, initializationVector, 0, 0, cn.Length);

            EncodeBlock(cn, encryptedData, 0, i + blockSizeInBytes, extendedKeyTable);

            Array.Copy(encryptedData, i + blockSizeInBytes, initializationVector, 0, cn.Length);
        }

        return encryptedData;
    }

    public byte[] Decode(byte[] input, byte[] key)
    {
        var blockSizeInBytes = BytesPerWord(_wordSize) * 2;
        var expandedKeyTable = GetExtendedKeyTable(key);
        var buffer = new byte[blockSizeInBytes];
        var decodedFileContent = new byte[input.Length - buffer.Length];

        DecodeBlock(input, buffer, 0, 0, expandedKeyTable);

        for (int i = blockSizeInBytes; i < input.Length; i += blockSizeInBytes)
        {
            var cn = new byte[blockSizeInBytes];
            Array.Copy(input, i, cn, 0, cn.Length);

            DecodeBlock(cn, decodedFileContent, 0, i - blockSizeInBytes, expandedKeyTable);

            Xor(decodedFileContent, buffer, i - blockSizeInBytes, 0, cn.Length);

            Array.Copy(input, i, buffer, 0, buffer.Length);
        }

        var decodedWithoutPadding = new byte[decodedFileContent.Length - decodedFileContent.Last()];
        Array.Copy(decodedFileContent, decodedWithoutPadding, decodedWithoutPadding.Length);

        return decodedWithoutPadding;
    }

    public void EncodeFile(string filePath, byte[] key, string encodedPath)
    {
        var data = File.ReadAllBytes(filePath);
        var encodedData = Encode(data, key);
        File.WriteAllBytes(encodedPath, encodedData);
    }

    public void DecodeFile(string originFilePath, byte[] key, string decodedPathDestination)
    {
        var data = File.ReadAllBytes(originFilePath);
        var decodedData = Decode(data, key);
        File.WriteAllBytes(decodedPathDestination, decodedData);
    }
}