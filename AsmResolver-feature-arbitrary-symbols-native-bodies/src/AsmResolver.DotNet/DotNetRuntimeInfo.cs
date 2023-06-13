using System;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace AsmResolver.DotNet
{
    /// <summary>
    /// Provides information about a target runtime.
    /// </summary>
    public readonly struct DotNetRuntimeInfo
    {
        /// <summary>
        /// The target framework name used by applications targeting .NET and .NET Core.
        /// </summary>
        public const string NetCoreApp = ".NETCoreApp";

        /// <summary>
        /// The target framework name used by libraries targeting .NET Standard.
        /// </summary>
        public const string NetStandard = ".NETStandard";

        /// <summary>
        /// The target framework name used by applications targeting legacy .NET Framework.
        /// </summary>
        public const string NetFramework = ".NETFramework";

        private static readonly Regex FormatRegex = new(@"([a-zA-Z.]+)\s*,\s*Version=v(\d+\.\d+)");

        /// <summary>
        /// Creates a new instance of the <see cref="DotNetRuntimeInfo"/> structure.
        /// </summary>
        /// <param name="name">The name of the runtime.</param>
        /// <param name="version">The version of the runtime.</param>
        public DotNetRuntimeInfo(string name, Version version)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Version = version ?? throw new ArgumentNullException(nameof(version));
        }

        /// <summary>
        /// Gets the name of the runtime.
        /// </summary>
        public string Name
        {
            get;
        }

        /// <summary>
        /// Gets the version of the runtime.
        /// </summary>
        public Version Version
        {
            get;
        }

        /// <summary>
        /// Gets a value indicating whether the application targets the .NET or .NET Core runtime or not.
        /// </summary>
        public bool IsNetCoreApp => Name == NetCoreApp;

        /// <summary>
        /// Gets a value indicating whether the application targets the .NET Framework runtime or not.
        /// </summary>
        public bool IsNetFramework => Name == NetFramework;

        /// <summary>
        /// Gets a value indicating whether the application targets the .NET standard specification or not.
        /// </summary>
        public bool IsNetStandard => Name == NetStandard;

        /// <summary>
        /// Attempts to parse the framework name as provided in <see cref="TargetFrameworkAttribute"/>.
        /// </summary>
        /// <param name="frameworkName">The full runtime name.</param>
        /// <param name="info">The parsed version info.</param>
        /// <returns><c>true</c> if the provided name was in the correct format, <c>false</c> otherwise.</returns>
        public static bool TryParse(string frameworkName, out DotNetRuntimeInfo info)
        {
            var match = FormatRegex.Match(frameworkName);
            if (!match.Success)
            {
                info = default;
                return false;
            }

            string name = match.Groups[1].Value;
            var version = new Version(match.Groups[2].Value);
            info = new DotNetRuntimeInfo(name, version);
            return true;
        }

        /// <inheritdoc />
        public override string ToString() => $"{Name},Version=v{Version}";
    }
}
