using System;

namespace AsmResolver.DotNet.Memory
{
    /// <summary>
    /// Defines members for all possible attributes that can be assigned to a <see cref="TypeMemoryLayout"/> instance.
    /// </summary>
    [Flags]
    public enum MemoryLayoutAttributes
    {
        /// <summary>
        /// Indicates the layout was determined assuming a 32-bit environment.
        /// </summary>
        Is32Bit = 0b0,

        /// <summary>
        /// Indicates the layout was determined assuming a 32-bit environment.
        /// </summary>
        Is64Bit = 0b1,

        /// <summary>
        /// Used to mask out the bitness of the type layout.
        /// </summary>
        BitnessMask = 0b1,

        /// <summary>
        /// Indicates the type layout depends on the bitness of the environment.
        /// </summary>
        IsPlatformDependent = 0b10,
    }
}
