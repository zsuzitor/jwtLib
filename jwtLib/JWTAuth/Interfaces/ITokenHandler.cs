using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface ITokenHandler
    {
        string GenerateMainToken(ClaimsIdentity identity);
        string GenerateRefreshToken();
        ClaimsPrincipal GetClaimsFromToken(string authorizationToken, out SecurityToken tokenSecure);
        JwtSecurityToken DecodeToken(string token);
    }
}