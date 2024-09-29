namespace Security.Labs.Algorithms.UnitTests;

public class LehmerGeneratorTests
{
    [Fact]
    public void GenerateSequence_ValidParameters_GeneratesCorrectCount()
    {
        // Arrange
        var generator = new LehmerGenerator(48271, 0, int.MaxValue, 1, 10, false);

        // Act
        var result = generator.GenerateSequence(out var period, out var firstPeriodOccurrence);

        // Assert
        Assert.Equal(10, result.Count);
        Assert.Null(period);
    }

    [Fact]
    public void GenerateSequence_OutputsToFile_WhenOutputToFileIsTrue()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        var generator = new LehmerGenerator(48271, 0, int.MaxValue, 1, 5, true);

        // Act
        var result = generator.GenerateSequence(out var period, out var firstPeriodOccurrence);

        // Assert
        var fileContents = File.ReadAllLines("GeneratedNumbers.txt");
        Assert.Equal(result.Count, fileContents.Length);

        // Clean up
        File.Delete("GeneratedNumbers.txt");
    }

    [Fact]
    public void GenerateSequence_DetectsPeriod_WhenSequenceRepeats()
    {
        // Arrange
        var generator = new LehmerGenerator(5, 1, 16, 3, 20, false); // Simple case for testing periodicity
        generator.GenerateSequence(out var period, out var firstPeriodOccurrence);

        // Act
        generator.GenerateSequence(out var period2, out var firstPeriodOccurrence2);

        // Assert
        Assert.NotNull(period2);
        Assert.True(period2 > 0);
        Assert.Equal(3, firstPeriodOccurrence2);
    }

    [Fact]
    public void GenerateSequence_CallsReportProgress_WhileGenerating()
    {
        // Arrange
        var generator = new LehmerGenerator(48271, 0, int.MaxValue, 1, 10, false);
        var progress = 0;

        // Act
        var result = generator.GenerateSequence(out var period, out var firstPeriodOccurrence,
            reportProgress: percent => progress = (int)percent);

        // Assert
        Assert.Equal(100, progress); // Ensure it reaches 100% completion
    }
}
