using System;
using System.Diagnostics;
using AsmResolver.Collections;
using AsmResolver.IO;
using AsmResolver.PE.File;
using AsmResolver.PE.File.Headers;

namespace AsmResolver.PE.Relocations
{
    /// <summary>
    /// Provides an implementation of a lazy-initialized list of base relocation entries, read from an existing PE file.
    /// </summary>
    [DebuggerDisplay("Count = {" + nameof(Count) + "}")]
    public class SerializedRelocationList : LazyList<BaseRelocation>
    {
        private readonly PEReaderContext _context;
        private readonly DataDirectory _relocDirectory;

        /// <summary>
        /// Prepares a new lazy-initialized list of base relocations.
        /// </summary>
        /// <param name="context">The reader context.</param>
        /// <param name="relocDirectory">The directory that contains the base relocations.</param>
        public SerializedRelocationList(PEReaderContext context, in DataDirectory relocDirectory)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _relocDirectory = relocDirectory;
        }

        /// <inheritdoc />
        protected override void Initialize()
        {
            if (!_context.File.TryCreateDataDirectoryReader(_relocDirectory, out var reader))
            {
                _context.BadImage("Invalid base relocation data directory RVA and/or size.");
                return;
            }

            while (reader.Offset < reader.StartOffset + reader.Length)
                ReadBlock(ref reader);
        }

        private void ReadBlock(ref BinaryStreamReader reader)
        {
            // Read block header.
            uint pageRva = reader.ReadUInt32();
            uint size = reader.ReadUInt32();

            // Read items.
            int count = (int) ((size - 2 * sizeof(uint)) / sizeof(ushort));
            for (int i = 0; i < count; i++)
                ReadRelocationEntry(ref reader, pageRva);
        }

        private void ReadRelocationEntry(ref BinaryStreamReader reader, uint pageRva)
        {
            ushort rawValue = reader.ReadUInt16();
            var type = (RelocationType) (rawValue >> 12);
            int offset = rawValue & 0xFFF;

            Items.Add(new BaseRelocation(type, _context.File.GetReferenceToRva((uint) (pageRva + offset))));
        }
    }
}
