
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
        bool ValidateRefreshToken(string userId, string refreshToken);
        TokenData GetCurrentDataFromToken(string authorizationToken, string key);
        Task<bool> DeleteRefreshTokenFromUserAsync(string userId, string refreshToken);
        string GenerateRefreshToken(ClaimsIdentity identity);
        string GenerateRefreshToken(IJWTUser user);
        string GetUserIdFromRefreshToken(string refreshToken);
        string GetUserIdFromAccessToken(string accessToken);
        ClaimsPrincipal GetClaimsFromAccessToken(string authorizationToken, out SecurityToken tokenSecure);
        ClaimsPrincipal GetClaimsFromRefreshToken(string authorizationToken, out SecurityToken tokenSecure);
        Task<IJWTUser> GetUserByRefreshTokenAsync(string userId, string refreshToken);
    }
}