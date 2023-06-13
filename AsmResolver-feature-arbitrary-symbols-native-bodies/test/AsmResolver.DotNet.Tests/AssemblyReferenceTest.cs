using System;
using System.Runtime.InteropServices;
using Xunit;

namespace AsmResolver.DotNet.Tests
{
    public class AssemblyReferenceTest
    {
        [Fact]
        public void ReadName()
        {
            var module = ModuleDefinition.FromBytes(Properties.Resources.HelloWorld);
            var assemblyRef = module.AssemblyReferences[0];
            Assert.Equal("mscorlib", assemblyRef.Name);
        }
        
        [Fact]
        public void ReadVersion()
        {
            var module = ModuleDefinition.FromBytes(Properties.Resources.HelloWorld);
            var assemblyRef = module.AssemblyReferences[0];
            Assert.Equal(new Version(4,0,0,0), assemblyRef.Version);
        }
        
        [Fact]
        public void ReadPublicKeyOrToken()
        {
            var module = ModuleDefinition.FromBytes(Properties.Resources.HelloWorld);
            var assemblyRef = module.AssemblyReferences[0];
            Assert.False(assemblyRef.HasPublicKey);
            var expectedToken = new byte[] {0xb7, 0x7a, 0x5c, 0x56, 0x19, 0x34, 0xe0, 0x89};
            Assert.Equal(expectedToken, assemblyRef.PublicKeyOrToken);
            Assert.Equal(expectedToken, assemblyRef.GetPublicKeyToken());
        }

        [Fact]
        public void CorLibResolution()
        {
            var module = ModuleDefinition.FromBytes(Properties.Resources.HelloWorld);
            var assemblyRef = module.AssemblyReferences[0];
            var assemblyDef = assemblyRef.Resolve();
            Assert.NotNull(assemblyDef);
            Assert.Equal(assemblyDef.Name, assemblyDef.Name);
            Assert.Equal(assemblyDef.Version, assemblyDef.Version);
        }
    }
}