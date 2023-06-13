using System.Linq;
using AsmResolver.Symbols.Pdb.Leaves;
using Xunit;
using static AsmResolver.Symbols.Pdb.Leaves.CodeViewFieldAttributes;

namespace AsmResolver.Symbols.Pdb.Tests.Leaves;

public class MethodListLeafTest : IClassFixture<MockPdbFixture>
{
    private readonly MockPdbFixture _fixture;

    public MethodListLeafTest(MockPdbFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void ReadNonIntroVirtualEntries()
    {
        var list = (MethodListLeaf) _fixture.SimplePdb.GetLeafRecord(0x2394);
        var entries = list.Entries;

        Assert.Equal(new[]
        {
            Public | CompilerGenerated,
            Public | CompilerGenerated,
            Private,
            Public,
        }, entries.Select(e => e.Attributes));

        Assert.All(entries, Assert.NotNull);
    }
}
