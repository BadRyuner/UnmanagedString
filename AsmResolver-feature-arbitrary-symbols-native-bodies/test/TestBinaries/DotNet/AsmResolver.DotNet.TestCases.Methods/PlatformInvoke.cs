using System;
using System.Runtime.InteropServices;

namespace AsmResolver.DotNet.TestCases.Methods
{
    public class PlatformInvoke
    {
        [DllImport("SomeDll.dll", EntryPoint = "SomeEntryPoint")]
        public static extern void ExternalMethod();

        [DllImport("SomeDll.dll")]
        public static extern void SimpleMarshaller([MarshalAs(UnmanagedType.Bool)] bool b);

        [DllImport("SomeDll.dll")]
        public static extern void LPArrayFixedSizeMarshaller([MarshalAs(UnmanagedType.LPArray, SizeConst = 10)] byte[] array);

        [DllImport("SomeDll.dll")]
        public static extern void LPArrayVariableSizeMarshaller([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] array, int count);

        [DllImport("SomeDll.dll")]
        public static extern void SafeArrayMarshaller([MarshalAs(UnmanagedType.SafeArray)] byte[] array);

        [DllImport("SomeDll.dll")]
        public static extern void SafeArrayMarshallerWithSubType([MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_UI1)] byte[] array);

        [DllImport("SomeDll.dll")]
        public static extern void SafeArrayMarshallerWithUserSubType(
            [MarshalAs(
                UnmanagedType.SafeArray,
                SafeArraySubType = VarEnum.VT_RECORD,
                SafeArrayUserDefinedSubType = typeof(PlatformInvoke))]
            byte[] array);


        [DllImport("SomeDll.dll")]
        public static extern void ComInterface([MarshalAs(UnmanagedType.Interface)] byte[] array);

        [DllImport("SomeDll.dll")]
        public static extern void ComInterfaceWithIidParameter(
            [MarshalAs(UnmanagedType.Interface, IidParameterIndex = 1)]
            byte[] array, Guid iid);

        public static void NonImplementationMapMethod()
        {
        }
    }
}
