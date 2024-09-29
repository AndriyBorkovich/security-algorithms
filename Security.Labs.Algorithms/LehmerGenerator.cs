namespace Security.Labs.Algorithms;

public sealed class LehmerGenerator(long A, long C, long M, long X0, int Count, bool OutputToFile)
{
    public List<long> GenerateSequence(out int? period, out int firstPeriodOccurrence, Action<double>? reportProgress = null)
    {
        var randomNumbers = new List<long>();
        var seenNumbers = new Dictionary<long, int>();
        period = null;
        firstPeriodOccurrence = -1;

        var current = X0;
        randomNumbers.Add(current);
        seenNumbers[current] = 0; // Track the first occurrence

        StreamWriter? writer = null;
        if (OutputToFile)
        {
            writer = new StreamWriter("GeneratedNumbers.txt");
            writer.WriteLine(current);
        }

        for (int i = 1; i < Count; i++)
        {
            current = (A * current + C) % M;
            randomNumbers.Add(current);
            if (OutputToFile)
            {
                writer?.WriteLine(current);
            }

            reportProgress?.Invoke(i * 100 / Count);

            if (period == null && seenNumbers.TryGetValue(current, out var previousIndex))
            {
                period = i - previousIndex;
                firstPeriodOccurrence = i;
            }
            else
            {
                seenNumbers[current] = i;
            }
        }

        writer?.Close();

        reportProgress?.Invoke(100);

        return randomNumbers;
    }
}
