namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTSettings
    {
        string Issuer { get; } // издатель токена
        string Audience { get; } // потребитель токена
        int Lfetime { get; } // время жизни токена - 1 минута
        string Key { get; } // ключ для шифрации
        int LengthRefreshToken { get; }
        string TokenName { get; }
    }
}