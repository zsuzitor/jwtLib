
using System.Security.Claims;
using System.Threading.Tasks;
using jwtLib.JWTAuth.Models.Poco;
using Microsoft.IdentityModel.Tokens;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTService
    {
        Task<AllTokens> Refresh(string userId, string refreshToken);
        Task<AllTokens> CreateAndSetNewTokens(IJWTUser user);
        Task<TokenData> GetCurrentDataFromToken(string authorizationToken, string key);
        Task DeleteRefreshTokenFromUser(string userId, string refreshToken);
        string GenerateRefreshToken(ClaimsIdentity identity);
        ClaimsPrincipal GetClaimsFromAccessToken(string authorizationToken, out SecurityToken tokenSecure);
        ClaimsPrincipal GetClaimsFromRefreshToken(string authorizationToken, out SecurityToken tokenSecure);
    }
}