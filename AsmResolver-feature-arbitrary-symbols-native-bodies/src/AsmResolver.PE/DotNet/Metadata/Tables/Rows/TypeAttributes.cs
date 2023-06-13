using System;

namespace AsmResolver.PE.DotNet.Metadata.Tables.Rows
{
    /// <summary>
    /// Provides members defining all flags that can be assigned to a type definition.
    /// </summary>
    [Flags]
    public enum TypeAttributes : uint
    {
        /// <summary>
        /// Class is not public scope.
        /// </summary>
        NotPublic = 0x00000000,
        /// <summary>
        /// Class is public scope.
        /// </summary>
        Public = 0x00000001, 
        /// <summary>
        /// Class is nested with public visibility.
        /// </summary>
        NestedPublic = 0x00000002, 
        /// <summary>
        /// Class is nested with private visibility.
        /// </summary>
        NestedPrivate = 0x00000003, 
        /// <summary>
        /// Class is nested with family visibility.
        /// </summary>
        NestedFamily = 0x00000004, 
        /// <summary>
        /// Class is nested with assembly visibility.
        /// </summary>
        NestedAssembly = 0x00000005, 
        /// <summary>
        /// Class is nested with family and assembly visibility.
        /// </summary>
        NestedFamilyAndAssembly = 0x00000006, 
        /// <summary>
        /// Class is nested with family or assembly visibility.
        /// </summary>
        NestedFamilyOrAssembly = 0x00000007,
        /// <summary>
        /// Provides a bitmask for obtaining flags related to visibility.
        /// </summary>
        VisibilityMask = 0x00000007,
        
        /// <summary>
        /// Class fields are auto-laid out
        /// </summary>
        AutoLayout = 0x00000000, 
        /// <summary>
        /// Class fields are laid out sequentially
        /// </summary>
        SequentialLayout = 0x00000008, 
        /// <summary>
        /// Layout is supplied explicitly
        /// </summary>
        ExplicitLayout = 0x00000010,
        /// <summary>
        /// Provides a bitmask for obtaining flags related to the layout of the type.
        /// </summary>
        LayoutMask = 0x00000018,

        /// <summary>
        /// BaseType is a class.
        /// </summary>
        Class = 0x00000000, 
        /// <summary>
        /// BaseType is an interface.
        /// </summary>
        Interface = 0x00000020, 
        /// <summary>
        /// Provides a bitmask for obtaining flags related to the semantics of the type.
        /// </summary>
        ClassSemanticsMask = 0x00000060,
        
        /// <summary>
        /// Class is abstract.
        /// </summary>
        Abstract = 0x00000080,
        /// <summary>
        /// Class is concrete and may not be extended.
        /// </summary>
        Sealed = 0x00000100, 
        /// <summary>
        /// Class name is special. Name describes how.
        /// </summary>
        SpecialName = 0x00000400,
        /// <summary>
        /// Runtime should check name encoding.
        /// </summary>
        RuntimeSpecialName = 0x00000800,
        /// <summary>
        /// Class / interface is imported.
        /// </summary>
        Import = 0x00001000,
        /// <summary>
        /// The class is Serializable.
        /// </summary>
        Serializable = 0x00002000, 


        /// <summary>
        /// LPTSTR is interpreted as ANSI in this class.
        /// </summary>
        AnsiClass = 0x00000000, 
        /// <summary>
        /// LPTSTR is interpreted as UNICODE.
        /// </summary>
        UnicodeClass = 0x00010000,
        /// <summary>
        /// LPTSTR is interpreted automatically
        /// </summary>
        AutoClass = 0x00020000,
        /// <summary>
        /// A non-standard encoding specified by CustomFormatMask.
        /// </summary>
        CustomFormatClass = 0x00030000,
        
        /// <summary>
        /// Provides a bitmask for obtaining flag related to string format.
        /// </summary>
        StringFormatMask = 0x00030000,

        /// <summary>
        /// Initialize the class any time before first static field access.
        /// </summary>
        BeforeFieldInit = 0x00100000,
        /// <summary>
        /// This ExportedType is a type forwarder.
        /// </summary>
        Forwarder = 0x00200000,

        /// <summary>
        /// Class has security associate with it.
        /// </summary>
        HasSecurity = 0x00040000,
    }
}