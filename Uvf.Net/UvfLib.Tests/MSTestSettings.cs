using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace Microsoft.VisualStudio.TestTools.UnitTesting
{
    /// <summary>
    /// Attribute to specify a display name for a test method.
    /// </summary>
    public class DisplayNameAttribute : Attribute
    {
        /// <summary>
        /// Gets the display name for the test method.
        /// </summary>
        public string DisplayName { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DisplayNameAttribute"/> class.
        /// </summary>
        /// <param name="displayName">The display name.</param>
        public DisplayNameAttribute(string displayName)
        {
            this.DisplayName = displayName;
        }
    }
}
