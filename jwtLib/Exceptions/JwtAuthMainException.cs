using System;

namespace jwtLib.Exceptions
{
    /// <summary>
    /// parrent for all custom jwt exception
    /// </summary>
    class JwtAuthMainException : Exception
    {
        public JwtAuthMainException() : base()
        {

        }

        public JwtAuthMainException(string message) : base(message)
        {

        }

        public JwtAuthMainException(string message, Exception innerIxcept) : base(message, innerIxcept)
        {

        }
    }
}
