

using System;

namespace jwtLib.Exceptions
{
    class JwtAuthNotValideRefreshToken : JwtAuthMainException
    {
        public JwtAuthNotValideRefreshToken() : base()
        {

        }

        public JwtAuthNotValideRefreshToken(string message) : base(message)
        {

        }

        public JwtAuthNotValideRefreshToken(string message, Exception innerIxcept) : base(message, innerIxcept)
        {

        }
    }
}
