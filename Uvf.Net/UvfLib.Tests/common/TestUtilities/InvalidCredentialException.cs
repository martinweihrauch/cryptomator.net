using System;

namespace UvfLib.Tests.Common.TestUtilities
{
    /// <summary>
    /// Exception thrown when credentials are invalid
    /// </summary>
    public class InvalidCredentialException : Exception
    {
        public InvalidCredentialException() : base()
        {
        }

        public InvalidCredentialException(string message) : base(message)
        {
        }

        public InvalidCredentialException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
} 