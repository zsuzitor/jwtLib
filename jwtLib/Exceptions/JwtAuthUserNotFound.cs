

using System;

namespace jwtLib.Exceptions
{
    /// <summary>
    /// JWTUserManager not return user
    /// </summary>
    class JwtAuthUserNotFound : JwtAuthMainException
    {
        public JwtAuthUserNotFound() : base()
        {

        }

        public JwtAuthUserNotFound(string message) : base(message)
        {

        }

        public JwtAuthUserNotFound(string message, Exception innerIxcept) : base(message, innerIxcept)
        {

        }
    }
}
