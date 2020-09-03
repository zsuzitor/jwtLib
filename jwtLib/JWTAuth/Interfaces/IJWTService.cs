
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Threading.Tasks;
using jwtLib.JWTAuth.Models.Poco;
using Microsoft.IdentityModel.Tokens;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTService
    {
        Task<AllTokens> RefreshAsync([NotNull] string userId, [NotNull] string refreshToken);
        Task<AllTokens> CreateAndSetNewTokensAsync([NotNull] IJWTUser user);
        bool ValidateRefreshToken([NotNull] string userId, [NotNull] string refreshToken);
        TokenData GetCurrentDataFromToken([NotNull] string authorizationToken, [NotNull] string key);
        Task<bool> DeleteRefreshTokenFromUserAsync([NotNull] string userId, [NotNull] string refreshToken);
        string GenerateRefreshToken([NotNull] ClaimsIdentity identity);
        string GenerateRefreshToken([NotNull] IJWTUser user);
        string GetUserIdFromRefreshToken([NotNull] string refreshToken);
        string GetUserIdFromAccessToken([NotNull] string accessToken);
        ClaimsPrincipal GetClaimsFromAccessToken([NotNull] string authorizationToken, out SecurityToken tokenSecure);
        ClaimsPrincipal GetClaimsFromRefreshToken([NotNull] string authorizationToken, out SecurityToken tokenSecure);
        Task<IJWTUser> GetUserByRefreshTokenAsync([NotNull] string userId, [NotNull] string refreshToken);
        Task<IJWTUser> GeUserByAccessTokenAsync([NotNull] string accessToken);

    }
}