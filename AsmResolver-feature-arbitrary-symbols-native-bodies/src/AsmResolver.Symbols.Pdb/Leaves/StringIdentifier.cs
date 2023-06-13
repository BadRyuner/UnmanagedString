namespace AsmResolver.Symbols.Pdb.Leaves;

/// <summary>
/// Represents a String ID entry within the IPI stream of a PDB image.
/// </summary>
public class StringIdentifier : CodeViewLeaf, IIpiLeaf
{
    private readonly LazyVariable<StringIdentifier, Utf8String> _value;
    private readonly LazyVariable<StringIdentifier, SubStringListLeaf?> _subStrings;

    /// <summary>
    /// Initializes an empty String ID entry.
    /// </summary>
    /// <param name="typeIndex">The type index.</param>
    protected StringIdentifier(uint typeIndex)
        : base(typeIndex)
    {
        _value = new LazyVariable<StringIdentifier, Utf8String>(x =>x .GetValue());
        _subStrings = new LazyVariable<StringIdentifier, SubStringListLeaf?>(x =>x .GetSubStrings());
    }

    /// <summary>
    /// Creates a new String ID entry.
    /// </summary>
    /// <param name="value">The string value to wrap.</param>
    public StringIdentifier(Utf8String value)
        : this(value, null)
    {
    }

    /// <summary>
    /// Creates a new String ID entry.
    /// </summary>
    /// <param name="value">The string value to wrap.</param>
    /// <param name="subStrings">A list of sub strings.</param>
    public StringIdentifier(Utf8String value, SubStringListLeaf? subStrings)
        : base(0)
    {
        _value = new LazyVariable<StringIdentifier, Utf8String>(value);
        _subStrings = new LazyVariable<StringIdentifier, SubStringListLeaf?>(subStrings);
    }

    /// <inheritdoc />
    public override CodeViewLeafKind LeafKind => CodeViewLeafKind.StringId;

    /// <summary>
    /// Gets or sets the wrapped string.
    /// </summary>
    public Utf8String Value
    {
        get => _value.GetValue(this);
        set => _value.SetValue(value);
    }

    /// <summary>
    /// Gets or sets a list of sub strings associated to the entry (if available).
    /// </summary>
    public SubStringListLeaf? SubStrings
    {
        get => _subStrings.GetValue(this);
        set => _subStrings.SetValue(value);
    }

    /// <summary>
    /// Obtains the wrapped string value.
    /// </summary>
    /// <returns>The string.</returns>
    /// <remarks>
    /// This method is called upon initialization of the <see cref="Value"/> property.
    /// </remarks>
    protected virtual Utf8String? GetValue() => null;

    /// <summary>
    /// Obtains the sub strings associated to the string.
    /// </summary>
    /// <returns>The sub string.</returns>
    /// <remarks>
    /// This method is called upon initialization of the <see cref="SubStrings"/> property.
    /// </remarks>
    protected virtual SubStringListLeaf? GetSubStrings() => null;

    /// <inheritdoc />
    public override string ToString()
    {
        return SubStrings is not null
            ? $"{Value} (Contains sub strings)"
            : Value;
    }
}
