using AsmResolver.IO;

namespace AsmResolver.Symbols.Pdb.Leaves.Serialized;

/// <summary>
/// Provides a lazily initialized implementation of <see cref="NonOverloadedMethod"/> that is read from a PDB image.
/// </summary>
public class SerializedNonOverloadedMethod : NonOverloadedMethod
{
    private readonly PdbReaderContext _context;
    private readonly uint _functionIndex;
    private readonly BinaryStreamReader _nameReader;

    /// <summary>
    /// Reads a non-overloaded method from the provided input stream.
    /// </summary>
    /// <param name="context">The reading context in which the method is situated in.</param>
    /// <param name="typeIndex">The index to assign to the type.</param>
    /// <param name="reader">The input stream to read from.</param>
    public SerializedNonOverloadedMethod(PdbReaderContext context, uint typeIndex, ref BinaryStreamReader reader)
        : base(typeIndex)
    {
        _context = context;
        Attributes = (CodeViewFieldAttributes) reader.ReadUInt16();
        _functionIndex = reader.ReadUInt32();
        if (IsIntroducingVirtual)
            VTableOffset = reader.ReadUInt32();
        _nameReader = reader.Fork();
        reader.AdvanceUntil(0, true);
    }

    /// <inheritdoc />
    protected override Utf8String GetName() => _nameReader.Fork().ReadUtf8String();

    /// <inheritdoc />
    protected override MemberFunctionLeaf? GetFunction()
    {
        return _context.ParentImage.TryGetLeafRecord(_functionIndex, out MemberFunctionLeaf? function)
            ? function
            : _context.Parameters.ErrorListener.BadImageAndReturn<MemberFunctionLeaf>(
                $"Method {TypeIndex:X8} contains an invalid function type index {_functionIndex:X8}.");
    }
}
