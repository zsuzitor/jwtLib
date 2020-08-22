
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTUserManager
    {
        Task<string> GetUserIdAsync(IJWTUser jwtUser);
        //Task<IJWTUser> GetUserAsync(string username, string password);

        Task<bool> ItIsUserClaims(List<Claim> claims, IJWTUser jwtUser);
        Task<bool> ItIsUserClaims(List<Claim> claims, string userId);

        Task<IJWTUser> GetWithRefreshTokenAsync(string userId, string refreshTokenHash);

        Task SetRefreshTokenAsync(IJWTUser jwtUser, string refreshToken);


        Task DeleteRefreshTokenFromUserAsync(string userId, string refreshToken);

        /// <summary>
        /// get data which will be saved in token
        /// </summary>
        /// <param name="jwtUser"></param>
        /// <param name="authenticationType">use for create ClaimsIdentity. google->"claimsidentity authenticationtype"</param>
        /// <returns></returns>
        Task<ClaimsIdentity> GetIdentityAsync(IJWTUser jwtUser, string authenticationType);

        Task<List<Claim>> GetIdentityForRefreshAsync(IJWTUser jwtUser);

        Task<string> GetIdFromClaimsAsync(ClaimsPrincipal claims);
        Task<string> GetIdFromClaimsAsync(IEnumerable<Claim> claims);


    }
}