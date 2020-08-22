namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTHasher
    {
        string GetHash(string token);
    }
}