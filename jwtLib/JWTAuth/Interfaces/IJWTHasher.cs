namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTHasher
    {
        string GetHashRefreshToken(string token);
    }
}