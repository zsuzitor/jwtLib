
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTUserManager
    {
        Task<string> GetUserIdAsync(IJWTUser jwtUser);
        Task<IJWTUser> GetUserAsync(string username, string password);
        Task<IJWTUser> GetWithRefreshTokenAsync(string userId, string refreshTokenHash);
        //Task<IJWTUser> GetByNameAsync(string name);
        //Task<bool> CheckPasswordAsync(IJWTUser user, string password);
        //Task SetRefreshTokenAsync(string userId, string refreshTokenHash);
        Task SetRefreshTokenAsync(IJWTUser jwtUser, string refreshTokenHash);
        Task DeleteRefreshTokenFromUserAsync(string userId, string refreshTokenHash);

        //Task<ClaimsIdentity> GetIdentityAsync(string username, string password, string authenticationType);
        Task<ClaimsIdentity> GetIdentityAsync(IJWTUser usjwtUserer, string authenticationType);

        Task<string> GetIdFromClaimsAsync(ClaimsPrincipal claims);
        Task<string> GetIdFromClaimsAsync(IEnumerable<Claim> claims);
    }
}