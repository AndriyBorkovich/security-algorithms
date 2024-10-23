namespace Security.Labs.Algorithms.Words;

public class Word16 : Word
{
    public ushort WordValue { get; set; }

    public Word16()
    {
        WordSizeInBits = 16;
    }

    public override int BytesPerWord()
    {
        return WordSizeInBits / 8;
    }

    public override void CreateFromBytes(byte[] bytes, int startFrom)
    {
        WordValue = 0;

        for (var i = startFrom + BytesPerWord() - 1; i > startFrom; --i)
        {
            WordValue |= bytes[i];
            WordValue <<= 8;
        }

        WordValue |= bytes[startFrom];
    }

    public override void ToBytes(byte[] bytesToFill, int startFrom)
    {
        var i = 0;
        for (; i < BytesPerWord() - 1; ++i)
        {
            bytesToFill[startFrom + i] = (byte)(WordValue & ByteMask);
            WordValue = (ushort)(WordValue >> 8);
        }

        bytesToFill[startFrom + i] = (byte)(WordValue & ByteMask);
    }

    public override Word CLS(int offset)
    {
        offset %= BytesPerWord();
        WordValue = (ushort)((WordValue << offset) | (WordValue >> (WordSizeInBits - offset)));
        return this;
    }

    public override Word CRS(int offset)
    {
        offset %= BytesPerWord();
        WordValue = (ushort)((WordValue >> offset) | (WordValue << (WordSizeInBits - offset)));
        return this;
    }

    public override Word Add(Word word)
    {
        WordValue += ((Word16)word).WordValue;
        return this;
    }

    public override Word Add(byte value)
    {
        WordValue += value;
        return this;
    }

    public override Word Sub(Word word)
    {
        WordValue -= ((Word16)word).WordValue;
        return this;
    }

    public override Word Xor(Word word)
    {
        WordValue ^= ((Word16)word).WordValue;
        return this;
    }

    public override Word Clone()
    {
        return new Word16() { WordSizeInBits = this.WordSizeInBits, WordValue = this.WordValue };
    }

    public override int ToInt32()
    {
        return WordValue;
    }
}
