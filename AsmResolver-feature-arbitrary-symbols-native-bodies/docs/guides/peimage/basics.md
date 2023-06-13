# Basic I/O

Every PE image interaction is done through classes defined by the
`AsmResolver.PE` namespace:

``` csharp
using AsmResolver.PE;
```

## Creating a new PE image

Creating a new image can be done by instantiating a `PEImage` class:

``` csharp
var peImage = new PEImage();
```

## Opening a PE image

Opening an image can be done through one of the [FromXXX]{.title-ref}
methods from the `PEImage` class:

``` csharp
byte[] raw = ...
var peImage = PEImage.FromBytes(raw);
```

``` csharp
var peImage = PEImage.FromFile(@"C:\myfile.exe");
```

``` csharp
IPEFile peFile = ...
var peImage = PEImage.FromFile(peFile);
```

``` csharp
BinaryStreamReader reader = ...
var peImage = PEImage.FromReader(reader);
```

If you want to read large files (+100MB), consider using memory mapped
I/O instead:

``` csharp
using var service = new MemoryMappedFileService();
var peImage = PEImage.FromFile(service.OpenFile(@"C:\myfile.exe"));
```

On Windows, if a module is loaded and mapped in memory (e.g. as a native
dependency or by the means of `LoadLibrary`), it is possible to load the
PE image from memory by providing the `HINSTANCE` (a.k.a. module base
address):

``` csharp
IntPtr hInstance = ...
var peImage = PEImage.FromModuleBaseAddress(hInstance);
```

## Writing a PE image

Building an image back to a PE file can be done manually by constructing
a `PEFile`, or by using one of the classes that implement the
`IPEFileBuilder` interface.

> [!NOTE]
> Currently AsmResolver only provides a full fletched builder for .NET
> images.

Building a .NET image can be done through the
`AsmResolver.PE.DotNet.Builder.ManagedPEFileBuilder` class:

``` csharp
var builder = new ManagedPEFileBuilder();
var newPEFile = builder.CreateFile(image);
```

Once a `PEFile` instance has been generated from the image, you can use
it to write the executable to an output stream (such as a file on the
disk or a memory stream).

``` csharp
using (var stream = File.Create(@"C:\mynewfile.exe"))
{
    var writer = new BinaryStreamWriter(stream);
    newPEFile.Write(writer);
}
```

For more information on how to construct arbitrary `PEFile` instances
for native images, look at [PE File Building](pe-building.md).

## Strong name signing

If the PE image is a .NET image, it can be signed with a strong-name.
Open a strong name private key from a file:

``` csharp
var snk = StrongNamePrivateKey.FromFile(@"C:\Path\To\keyfile.snk");
```

Make sure that the strong name directory is present and has the correct
size.

``` csharp
image.DotNetDirectory.StrongName = new DataSegment(new byte[snk.Modulus.Length]);
```

After writing the PE image to an output stream, use the
`StrongNameSigner` class to sign the image.

``` csharp
using Stream outputStream = ...

var signer = new StrongNameSigner(snk);
signer.SignImage(outputStream, module.Assembly.HashAlgorithm);
```
