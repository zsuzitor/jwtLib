using System.Diagnostics.CodeAnalysis;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTHasher
    {
        string GetHash([NotNull] string token);
    }
}