

using System;

namespace jwtLib.Exceptions
{
    class JwtAuthIdentityDataIsBad : JwtAuthMainException
    {
        public JwtAuthIdentityDataIsBad() : base()
        {

        }

        public JwtAuthIdentityDataIsBad(string message) : base(message)
        {

        }

        public JwtAuthIdentityDataIsBad(string message, Exception innerIxcept) : base(message, innerIxcept)
        {

        }
    }
}
