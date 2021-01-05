using System;

namespace jwtLib.Exceptions
{
    class JwtAuthBadToken : JwtAuthMainException
    {
        public JwtAuthBadToken() : base()
        {

        }

        public JwtAuthBadToken(string message) : base(message)
        {

        }

        public JwtAuthBadToken(string message, Exception innerIxcept) : base(message, innerIxcept)
        {

        }
    }
}
