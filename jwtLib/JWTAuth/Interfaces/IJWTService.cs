
using System.Security.Claims;
using System.Threading.Tasks;
using jwtLib.JWTAuth.Models.Poco;
using Microsoft.IdentityModel.Tokens;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTService
    {
        Task<AllTokens> RefreshAsync(string userId, string refreshToken);
        Task<AllTokens> CreateAndSetNewTokensAsync(IJWTUser user);
        Task<bool> ValidateRefreshTokenAsync(string userId, string refreshToken);
        Task<TokenData> GetCurrentDataFromTokenAsync(string authorizationToken, string key);
        Task<bool> DeleteRefreshTokenFromUserAsync(string userId, string refreshToken);
        string GenerateRefreshToken(ClaimsIdentity identity);
        Task<string> GenerateRefreshTokenAsync(IJWTUser user);
        Task<string> GetUserIdFromRefreshTokenAsync(string refreshToken);
        ClaimsPrincipal GetClaimsFromAccessToken(string authorizationToken, out SecurityToken tokenSecure);
        ClaimsPrincipal GetClaimsFromRefreshToken(string authorizationToken, out SecurityToken tokenSecure);
        Task<IJWTUser> GetUserByRefreshTokenAsync(string userId, string refreshToken);
    }
}