using jwtLib.JWTAuth.Interfaces;

namespace jwtLibUsage.Example
{
    public class JWTServiceSettings : IJWTServiceSettings
    {
       
        public int LifetimeAccessToken => 1;
        public int LifetimeRefreshToken => 2;
        public string KeyForAccessToken => "mysupersecret_secretkey!123";
        public string KeyForRefreshToken => "mysupersecret_secretkey!321";
        public string AuthenticationType => "authentication_type";

    }
}