using jwtLib.JWTAuth.Interfaces;

namespace jwtLibUsage.Example
{
    public class JWTSettings : IJWTSettings
    {
        public string Issuer => "MyAuthServer";
        public string Audience => "http://localhost:51884/";
        public int Lfetime => 1;
        public string Key => "mysupersecret_secretkey!123";
        public int LengthRefreshToken => 10;
        public string TokenName => "AuthToken";
    }
}