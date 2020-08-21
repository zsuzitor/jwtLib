

using jwtLib.JWTAuth.Interfaces;

namespace jwtLibUsage.Example
{
    public class JWTSettings: IJWTSettings
    {
        public string Issuer => "MyAuthServer";
        public string Audience => "http://localhost:51884/";
        public string TokenName => "AuthToken";
    }
}
