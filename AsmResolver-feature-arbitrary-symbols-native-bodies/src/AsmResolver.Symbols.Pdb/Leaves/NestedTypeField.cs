namespace AsmResolver.Symbols.Pdb.Leaves;

/// <summary>
/// Represents a field in a type that references a nested type definition.
/// </summary>
public class NestedTypeField : CodeViewNamedField
{
    private readonly LazyVariable<NestedTypeField, CodeViewTypeRecord?> _type;

    /// <summary>
    /// Initializes an empty nested type.
    /// </summary>
    /// <param name="typeIndex">The type index to assign to the nested type field.</param>
    protected NestedTypeField(uint typeIndex)
        : base(typeIndex)
    {
        _type = new LazyVariable<NestedTypeField, CodeViewTypeRecord?>(x => x.GetNestedType());
    }

    /// <summary>
    /// Creates a new nested type field.
    /// </summary>
    /// <param name="type">The definition of the nested type</param>
    /// <param name="name">The name of the nested type.</param>
    public NestedTypeField(CodeViewTypeRecord type, Utf8String name)
        : base(0)
    {
        _type = new LazyVariable<NestedTypeField, CodeViewTypeRecord?>(type);
        Name = name;
        Attributes = 0;
    }

    /// <summary>
    /// Creates a new nested type (extended) field.
    /// </summary>
    /// <param name="type">The definition of the nested type</param>
    /// <param name="name">The name of the nested type.</param>
    /// <param name="attributes">The attributes assigned to the type.</param>
    public NestedTypeField(CodeViewTypeRecord type, Utf8String name, CodeViewFieldAttributes attributes)
        : base(0)
    {
        _type = new LazyVariable<NestedTypeField, CodeViewTypeRecord?>(type);
        Name = name;
        Attributes = attributes;
    }

    /// <inheritdoc />
    public override CodeViewLeafKind LeafKind => Attributes == 0
        ? CodeViewLeafKind.NestType
        : CodeViewLeafKind.NestTypeEx;

    /// <summary>
    /// Gets or sets the definition of the referenced nested type.
    /// </summary>
    public CodeViewTypeRecord? Type
    {
        get => _type.GetValue(this);
        set => _type.SetValue(value);
    }

    /// <summary>
    /// Obtains the definition of the nested type.
    /// </summary>
    /// <returns>The type</returns>
    /// <remarks>
    /// This method is called upon initialization of the <see cref="Type"/> property.
    /// </remarks>
    protected virtual CodeViewTypeRecord? GetNestedType() => null;
}
