namespace AsmResolver.PE.Imports.Builder
{
    /// <summary>
    /// Provides a mechanism for building an import address directory in a PE file.
    /// </summary>
    public class ImportAddressDirectoryBuffer : ImportDirectoryBufferBase
    {
        /// <summary>
        /// Creates a new import address directory buffer, using the provided hint-name table to obtain addresses to names
        /// of an imported member.
        /// </summary>
        /// <param name="hintNameTable">The hint-name table that is used to reference names of modules or members.</param>
        /// <param name="is32Bit">Indicates the import directory should use 32-bit addresses or 64-bit addresses.</param>
        public ImportAddressDirectoryBuffer(HintNameTableBuffer hintNameTable, bool is32Bit)
            : base(hintNameTable, is32Bit)
        {
        }

        /// <inheritdoc />
        public override void UpdateOffsets(in RelocationParameters parameters)
        {
            base.UpdateOffsets(parameters);

            var current = parameters;
            for (int i = 0; i < Modules.Count; i++)
            {
                var module = Modules[i];

                var thunkTable = GetModuleThunkTable(module);
                uint size = thunkTable.GetPhysicalSize();
                thunkTable.UpdateOffsets(current);
                current.Advance(size);
            }
        }

        /// <inheritdoc />
        protected override ThunkTableBuffer CreateThunkTable() => new(HintNameTable, Is32Bit, true);
    }
}
