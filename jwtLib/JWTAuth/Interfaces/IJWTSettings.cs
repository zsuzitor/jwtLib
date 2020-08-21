

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTSettings
    {
        string Issuer { get; } // издатель токена
        string Audience { get; } // потребитель токена
        string TokenName { get; }
    }
}
