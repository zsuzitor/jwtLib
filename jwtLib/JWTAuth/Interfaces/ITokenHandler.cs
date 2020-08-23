using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface ITokenHandler
    {
        string GenerateToken([NotNull] ClaimsIdentity identity, int lifeTimeInMinute, [NotNull] string key);
        //string GenerateRefreshToken(string userId);
        ClaimsPrincipal GetClaimsFromToken([NotNull] string authorizationToken, 
            [NotNull] string key, [NotNull] out SecurityToken tokenSecure);

        JwtSecurityToken DecodeToken([NotNull] string token);
    }
}