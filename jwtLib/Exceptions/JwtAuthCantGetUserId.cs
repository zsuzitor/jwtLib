

using System;

namespace jwtLib.Exceptions
{
    /// <summary>
    /// cant get userId from JWTUserManager
    /// </summary>
    class JwtAuthCantGetUserId : JwtAuthMainException
    {

        public JwtAuthCantGetUserId() : base()
        {

        }

        public JwtAuthCantGetUserId(string message) : base(message)
        {

        }

        public JwtAuthCantGetUserId(string message, Exception innerIxcept) : base(message, innerIxcept)
        {

        }
    }
}
