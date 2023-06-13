using AsmResolver.IO;
using AsmResolver.Symbols.Pdb.Leaves;

namespace AsmResolver.Symbols.Pdb.Records.Serialized;

/// <summary>
/// Represents a lazily initialized implementation of <see cref="RegisterRelativeSymbol"/> that is read from a PDB image.
/// </summary>
public class SerializedRegisterRelativeSymbol : RegisterRelativeSymbol
{
    private readonly PdbReaderContext _context;
    private readonly uint _typeIndex;
    private readonly BinaryStreamReader _nameReader;

    /// <summary>
    /// Reads a register+offset pair symbol from the provided input stream.
    /// </summary>
    /// <param name="context">The reading context in which the symbol is situated in.</param>
    /// <param name="reader">The input stream to read from.</param>
    public SerializedRegisterRelativeSymbol(PdbReaderContext context, BinaryStreamReader reader)
    {
        _context = context;

        Offset = reader.ReadInt32();
        _typeIndex = reader.ReadUInt32();
        BaseRegister = reader.ReadUInt16();

        _nameReader = reader;
    }

    /// <inheritdoc />
    protected override Utf8String GetName() => _nameReader.Fork().ReadUtf8String();

    /// <inheritdoc />
    protected override CodeViewTypeRecord? GetVariableType()
    {
        return _context.ParentImage.TryGetLeafRecord(_typeIndex, out CodeViewTypeRecord? type)
            ? type
            : _context.Parameters.ErrorListener.BadImageAndReturn<CodeViewTypeRecord>(
                $"Relative register symbol contains an invalid type index {_typeIndex:X8}.");
    }
}
