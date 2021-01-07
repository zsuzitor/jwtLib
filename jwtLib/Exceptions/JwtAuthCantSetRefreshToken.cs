


using System;

namespace jwtLib.Exceptions
{
    /// <summary>
    /// JWTUserManager.SetRefreshTokenAsync return false
    /// </summary>
    class JwtAuthCantSetRefreshToken : JwtAuthMainException
    {
        public JwtAuthCantSetRefreshToken() : base()
        {

        }

        public JwtAuthCantSetRefreshToken(string message) : base(message)
        {

        }

        public JwtAuthCantSetRefreshToken(string message, Exception innerIxcept) : base(message, innerIxcept)
        {

        }
    }
}
