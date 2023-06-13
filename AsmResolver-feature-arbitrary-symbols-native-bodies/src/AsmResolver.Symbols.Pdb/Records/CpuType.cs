namespace AsmResolver.Symbols.Pdb.Records;

/// <summary>
/// Provides members for all possible target CPUs that an executable file can target.
/// </summary>
public enum CpuType : ushort
{
#pragma warning disable CS1591
    Intel8080 = 0x0,
    Intel8086 = 0x1,
    Intel80286 = 0x2,
    Intel80386 = 0x3,
    Intel80486 = 0x4,
    Pentium = 0x5,
    PentiumPro = 0x6,
    Pentium3 = 0x7,
    Mips = 0x10,
    Mips16 = 0x11,
    Mips32 = 0x12,
    Mips64 = 0x13,
    MipsI = 0x14,
    MipsII = 0x15,
    MipsIII = 0x16,
    MipsIV = 0x17,
    MipsV = 0x18,
    M68000 = 0x20,
    M68010 = 0x21,
    M68020 = 0x22,
    M68030 = 0x23,
    M68040 = 0x24,
    Alpha = 0x30,
    Alpha21164 = 0x31,
    Alpha21164A = 0x32,
    Alpha21264 = 0x33,
    Alpha21364 = 0x34,
    Ppc601 = 0x40,
    Ppc603 = 0x41,
    Ppc604 = 0x42,
    Ppc620 = 0x43,
    PpcFP = 0x44,
    PpcBE = 0x45,
    SH3 = 0x50,
    SH3E = 0x51,
    SH3DSP = 0x52,
    SH4 = 0x53,
    SHMedia = 0x54,
    Arm3 = 0x60,
    Arm4 = 0x61,
    Arm4T = 0x62,
    Arm5 = 0x63,
    Arm5T = 0x64,
    Arm6 = 0x65,
    ArmXmac = 0x66,
    ArmWmmx = 0x67,
    Arm7 = 0x68,
    Omni = 0x70,
    IA64 = 0x80,
    IA64_2 = 0x81,
    Cee = 0x90,
    AM33 = 0xa0,
    M32R = 0xb0,
    TriCore = 0xc0,
    X64 = 0xd0,
    EBC = 0xe0,
    Thumb = 0xf0,
    ArmNT = 0xf4,
    Arm64 = 0xf6,
    HybridX86Arm64 = 0xf7,
    Arm64EC = 0xf8,
    Arm64X = 0xf9,
    D3D11Shader = 0x100,
#pragma warning restore CS1591
}
