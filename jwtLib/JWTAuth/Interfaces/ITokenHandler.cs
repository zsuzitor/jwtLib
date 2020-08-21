using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface ITokenHandler
    {
        string GenerateToken(ClaimsIdentity identity, int lifeTimeInMinute, string key);
        //string GenerateRefreshToken(string userId);
        ClaimsPrincipal GetClaimsFromToken(string authorizationToken, string key, out SecurityToken tokenSecure);

        JwtSecurityToken DecodeToken(string token);
    }
}