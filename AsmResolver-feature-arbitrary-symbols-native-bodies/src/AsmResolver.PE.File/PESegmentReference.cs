using System;
using AsmResolver.IO;

namespace AsmResolver.PE.File
{
    /// <summary>
    /// Represents a reference to a segment of a PE file.
    /// </summary>
    public sealed class PESegmentReference : ISegmentReference
    {
        private readonly IPEFile _peFile;

        /// <summary>
        /// Creates a new PE reference.
        /// </summary>
        /// <param name="peFile">The underlying PE file.</param>
        /// <param name="rva">The virtual address of the segment.</param>
        internal PESegmentReference(IPEFile peFile, uint rva)
        {
            _peFile = peFile;
            Rva = rva;
        }

        /// <inheritdoc />
        public ulong Offset => _peFile.TryGetSectionContainingRva(Rva, out _)
            ? _peFile.RvaToFileOffset(Rva)
            : 0u;

        /// <inheritdoc />
        public uint Rva
        {
            get;
        }

        /// <inheritdoc />
        public bool CanRead => _peFile.TryGetSectionContainingRva(Rva, out var section) && section.IsReadable;

        /// <inheritdoc />
        public bool IsBounded => false;

        /// <summary>
        /// Gets a value indicating whether the reference points to a valid section within the PE file.
        /// </summary>
        public bool IsValidAddress => _peFile.TryGetSectionContainingRva(Rva, out _);

        /// <inheritdoc />
        public BinaryStreamReader CreateReader() => _peFile.CreateReaderAtRva(Rva);

        /// <inheritdoc />
        public ISegment? GetSegment() => throw new InvalidOperationException();

        /// <inheritdoc />
        public override string ToString() => $"0x{Rva:X8}";
    }
}
