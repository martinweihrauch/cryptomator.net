using System;

namespace CryptomatorLib.Tests.Common.TestUtilities
{
    /// <summary>
    /// A mock implementation of InvalidCredentialException for testing
    /// This simulates the behavior of a similar class from Java
    /// </summary>
    public class InvalidCredentialException : Exception
    {
        public InvalidCredentialException() : base() { }
        
        public InvalidCredentialException(string message) : base(message) { }
        
        public InvalidCredentialException(string message, Exception innerException) 
            : base(message, innerException) { }
    }
} 