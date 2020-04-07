using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using jwtLib.JWTAuth.Models.Poco;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTService
    {
        Task<AllTokens> Refresh(string userId, string refreshToken);
        Task<AllTokens> Refresh(IJWTUser user);
        Task<TokenData> GetCurrentIdFromToken(string authorizationToken);
        Task DeleteRefreshTokenFromUser(string userId, string refreshToken);
    }
}