using System;

namespace jwtLib.Exceptions
{
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
