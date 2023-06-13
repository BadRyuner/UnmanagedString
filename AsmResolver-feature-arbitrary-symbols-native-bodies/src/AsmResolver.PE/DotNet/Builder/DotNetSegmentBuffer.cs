using AsmResolver.IO;

namespace AsmResolver.PE.DotNet.Builder
{
    /// <summary>
    /// Provides a mechanism for building a segment in a PE file containing .NET metadata.
    /// </summary>
    public class DotNetSegmentBuffer : ISegment
    {
        private readonly SegmentBuilder _segments;

        /// <summary>
        /// Creates a new .NET segment buffer.
        /// </summary>
        /// <param name="dotNetDirectory">The .NET directory to base it on.</param>
        public DotNetSegmentBuffer(IDotNetDirectory dotNetDirectory)
        {
            _segments = new SegmentBuilder
            {
                (DotNetDirectory = dotNetDirectory),
                (FieldRvaTable = new SegmentBuilder()),
                (MethodBodyTable = new MethodBodyTableBuffer())
            };

            AddIfPresent(dotNetDirectory.Metadata);
            AddIfPresent(dotNetDirectory.DotNetResources);
            AddIfPresent(dotNetDirectory.StrongName);

            if (dotNetDirectory.VTableFixups?.Count > 0)
                _segments.Add(dotNetDirectory.VTableFixups);

            AddIfPresent(dotNetDirectory.ExportAddressTable);
            AddIfPresent(dotNetDirectory.ManagedNativeHeader);
        }

        /// <inheritdoc />
        public ulong Offset => _segments.Offset;

        /// <inheritdoc />
        public uint Rva => _segments.Rva;

        /// <inheritdoc />
        public bool CanUpdateOffsets => _segments.CanUpdateOffsets;

        /// <summary>
        /// Gets the .NET directory header.
        /// </summary>
        public IDotNetDirectory DotNetDirectory
        {
            get;
        }

        /// <summary>
        /// Gets a table containing all constants used as initial values for fields defined in the .NET assembly.
        /// </summary>
        public SegmentBuilder FieldRvaTable
        {
            get;
        }

        /// <summary>
        /// Gets a table containing method bodies for methods defined in the .NET assembly.
        /// </summary>
        public MethodBodyTableBuffer MethodBodyTable
        {
            get;
        }

        private void AddIfPresent(ISegment? segment)
        {
            if (segment is not null)
                _segments.Add(segment, 4);
        }

        /// <inheritdoc />
        public void UpdateOffsets(in RelocationParameters parameters) => _segments.UpdateOffsets(parameters);

        /// <inheritdoc />
        public uint GetPhysicalSize() => _segments.GetPhysicalSize();

        /// <inheritdoc />
        public uint GetVirtualSize() => _segments.GetVirtualSize();

        /// <inheritdoc />
        public void Write(IBinaryStreamWriter writer) => _segments.Write(writer);
    }
}
