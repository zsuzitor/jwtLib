using jwtLib.JWTAuth.Interfaces;

namespace jwtLibUsage.Example
{
    public class JWTServiceSettings : IJWTServiceSettings
    {
       
        public int LifetimeAccessToken => 1;
        public int LifetimeRefreshToken => 2;
        public string KeyForAccessToken => "mysupersecret_secretkey!1239999999998888";
        public string KeyForRefreshToken => "mysupersecret_secretkey!321999999996666";
        public string AuthenticationType => "authentication_type";

    }
}