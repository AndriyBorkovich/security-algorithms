namespace Security.Labs.Algorithms.Words;

public abstract class Word
{
    public int WordSizeInBits { get; set; }
    public const int ByteMask = 0b11111111;

    public abstract int BytesPerWord();

    public abstract void CreateFromBytes(byte[] bytes, int startFrom);

    public abstract void ToBytes(byte[] bytesToFill, int startFrom);

    public abstract Word CLS(int offset);

    public abstract Word CRS(int offset);

    public abstract Word Add(Word word);

    public abstract Word Add(byte value);

    public abstract Word Sub(Word word);

    public abstract Word Xor(Word word);

    public abstract Word Clone();

    public abstract int ToInt32();
}
