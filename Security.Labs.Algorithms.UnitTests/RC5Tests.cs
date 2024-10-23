namespace Security.Labs.Algorithms.UnitTests;

public class RC5Tests
{
    [Theory]
    [MemberData(nameof(GetTestCases))]
    public void TestMethod(int w, int r, int b)
    {
        string dataString = "Security is cool", key = "abcd";
        var originDataBytes = HelperMethods.StringToBytes(dataString);
        var hashedKey = HelperMethods.GetHashedKey(HelperMethods.StringToBytes(key), b);

        var rc5 = new RC5(w, r, b);
        var encodedData = rc5.Encode(originDataBytes, hashedKey);
        var decodedData = rc5.Decode(encodedData, hashedKey);

        var decodedString = HelperMethods.BytesToString(decodedData);
        Assert.Equal(dataString, decodedString);
    }

    public static IEnumerable<object[]> GetTestCases()
    {
        return
        [
            [16, 8, 16],
            [32, 12, 16],
            [64, 16, 32],
            [16, 20, 16],
            [32, 8, 32],
            [64, 12, 8],
            [16, 16, 8],
            [32, 20, 16],
            [64, 8, 32],
            [16, 12, 16],
            [32, 16, 8],
            [64, 20, 16],
            [16, 8, 32],
            [32, 12, 32],
            [64, 16, 16],
            [16, 20, 8],
            [32, 8, 8],
            [64, 12, 16],
            [16, 16, 32],
            [32, 20, 32],
            [64, 8, 16],
            [16, 12, 8],
            [32, 16, 32],
            [64, 20, 8],
            [16, 8, 8],
        ];
    }

}