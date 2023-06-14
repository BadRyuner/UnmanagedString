using System.Text;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Code.Native;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables.Rows;
using AsmResolver.PE.File.Headers;
using MethodDefinition = AsmResolver.DotNet.MethodDefinition;
using ModuleDefinition = AsmResolver.DotNet.ModuleDefinition;
using Reloaded.Assembler;
using AsmResolver;
using AsmResolver.PE.DotNet.Builder;
using AsmResolver.PE.File;
using System.Runtime.CompilerServices;

namespace UnmanagedString;

public unsafe static class EntryPoint
{
    public static byte[] trampoline;
    public static List<DataSegment> AllSegs = new(4);

    static EntryPoint()
	{
		using var asm = new Assembler();
        trampoline = asm.Assemble("use64\nlea rax, [stringKlass]\nret\nstringKlass:\ndq 0");
	}

    public static void Main(string[] args)
    {
        //args = new[] { "D:\\WorkRn\\U\\src\\Test\\bin\\Debug\\net6.0\\Test.dll" };
        if (args.Length != 1)
        {
            Logger.Error("Usage: UnmanagedString.exe <path to assembly>");
            return;
        }

        if (!File.Exists(args[0]))
        {
            Logger.Error($"File not found: {args[0]}");
            return;
        }

        var module = ModuleDefinition.FromFile(args[0]);
        var importer = new ReferenceImporter(module);

        Logger.Information("Starting...");

        module.IsILOnly = false;
        var isx86 = module.MachineType == MachineType.I386;

        if (isx86)
        {
            module.PEKind = OptionalHeaderMagic.PE32;
            module.MachineType = MachineType.I386;
            module.Attributes |= DotNetDirectoryFlags.Bit32Required;
        }
        else
        {
            module.PEKind = OptionalHeaderMagic.PE32Plus;
            module.MachineType = MachineType.Amd64;
        }
        var fix = new MethodDefinition("Fix", MethodAttributes.Public | MethodAttributes.Static, MethodSignature.CreateStatic(module.CorLibTypeFactory.Void, module.CorLibTypeFactory.IntPtr));
        module.GetOrCreateModuleType().Methods.Add(fix);
        var fb = new CilMethodBody(fix);
		fix.CilMethodBody = fb;
        fb.Instructions.Add(CilOpCodes.Ldarg_0);
        fb.Instructions.Add(CilOpCodes.Ldind_I);
        fb.Instructions.Add(CilOpCodes.Ldtoken, module.CorLibTypeFactory.String.ToTypeDefOrRef());
        fb.Instructions.Add(CilOpCodes.Stind_I);
        fb.Instructions.Add(CilOpCodes.Ret);

		List<MethodDefinition> nativestrings = new List<MethodDefinition>();

        foreach (var type in module.GetAllTypes())
        foreach (var method in type.Methods)
            for (var index = 0; index < method.CilMethodBody?.Instructions.Count; ++index)
            {
                var instruction = method.CilMethodBody!.Instructions[index];

                if (instruction.OpCode != CilOpCodes.Ldstr)
                    continue;

                var newNativeMethod =
                    CreateNewNativeMethodWithString(
                        instruction.Operand as string ?? throw new InvalidCilInstructionException(), module, isx86);

                nativestrings.Add(newNativeMethod);

                if (newNativeMethod == null)
                    continue;

                instruction.OpCode = CilOpCodes.Call;
                instruction.Operand = newNativeMethod;

                method.CilMethodBody.Instructions.Insert(++index,
                    new CilInstruction(CilOpCodes.Ldind_Ref));
            }

        var cctor = module.GetOrCreateModuleConstructor().CilMethodBody.Instructions;
        foreach(var i in nativestrings)
        {
            cctor.Insert(0, new CilInstruction(CilOpCodes.Call, i));
            cctor.Insert(1, new CilInstruction(CilOpCodes.Call, fix));
        }

        var peimage = module.ToPEImage();
        var pegen = new ManagedPEFileBuilder();
        var pefile = pegen.CreateFile(peimage);
        var strings = new PESection(".strs", SectionFlags.MemoryWrite | SectionFlags.MemoryRead);
        pefile.Sections.Add(strings);
        var container = new SegmentBuilder();
        strings.Contents = container;
        foreach(var d in AllSegs)
        {
            container.Add(d);
        }
        pefile.Write(args[0]);
        Logger.Success("Done!");
    }

    private static MethodDefinition CreateNewNativeMethodWithString(string toInject, ModuleDefinition originalModule,
        bool isX86)
    {
        if (originalModule == null)
            throw new ArgumentNullException(nameof(originalModule));

        var factory = originalModule.CorLibTypeFactory;

        // Create new method with public and static visibility.
        var methodName = Guid.NewGuid().ToString();
        var method = new MethodDefinition(methodName, MethodAttributes.Public | MethodAttributes.Static,
            MethodSignature.CreateStatic(factory.IntPtr));

        // Set ImplAttributes to NativeBody.
        method.ImplAttributes |= MethodImplAttributes.Native | MethodImplAttributes.Unmanaged |
                                 MethodImplAttributes.PreserveSig;

        // Set Attributes to PinvokeImpl.
        method.Attributes |= MethodAttributes.PInvokeImpl;

        originalModule.GetOrCreateModuleType().Methods.Add(method);

        var strbytes = Encoding.Unicode.GetBytes(toInject + '\0');
        var klass = new byte[strbytes.Length+8+4];
        strbytes.CopyTo(klass, 8+4); // wtf, it cant copy last char +_+
        fixed(byte* p = &klass[8])
        {
            *(int*)p = toInject.Length;
        }

        // Create a new NativeMethodBody with x64 or x32 byte code.
        NativeMethodBody body;

        if (isX86)
            throw new NotImplementedException();
        else
        {
			body = new NativeMethodBody(method)
			{
				Code = trampoline
			};
            var seg = new DataSegment(klass);
            var symbol = new Symbol(new SegmentReference(seg));
            body.AddressFixups.Add(new AsmResolver.PE.Code.AddressFixup((uint)(trampoline.Length-8), AsmResolver.PE.Code.AddressFixupType.Absolute64BitAddress, symbol));
            AllSegs.Add(seg);		
        }

        Logger.Success($"Created new native method with name: {methodName} for string: {toInject}");
        method.NativeMethodBody = body;
        return method;
    }
}