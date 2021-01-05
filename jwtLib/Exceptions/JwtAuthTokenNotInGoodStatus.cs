
using System;

namespace jwtLib.Exceptions
{
    class JwtAuthTokenNotInGoodStatus : JwtAuthMainException
    {
        public JwtAuthTokenNotInGoodStatus() : base()
        {

        }

        public JwtAuthTokenNotInGoodStatus(string message) : base(message)
        {

        }

        public JwtAuthTokenNotInGoodStatus(string message, Exception innerIxcept) : base(message, innerIxcept)
        {

        }
    }
}
