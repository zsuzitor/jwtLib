using System;

namespace jwtLib.Exceptions
{

    /// <summary>
    /// not valide\bad token
    /// </summary>
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
