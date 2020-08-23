
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTUserManager
    {
        string GetUserId(IJWTUser jwtUser);
        //Task<IJWTUser> GetUserAsync(string username, string password);

        bool ItIsUserClaims(IEnumerable<Claim> claims, IJWTUser jwtUser);
        bool ItIsUserClaims(IEnumerable<Claim> claims, string userId);

        Task<IJWTUser> GetWithRefreshTokenAsync(string userId, string refreshTokenHash);

        Task<bool> SetRefreshTokenAsync(IJWTUser jwtUser, string refreshToken);


        Task<bool> DeleteRefreshTokenFromUserAsync(string userId, string refreshToken);

        /// <summary>
        /// get data which will be saved in token
        /// </summary>
        /// <param name="jwtUser"></param>
        /// <param name="authenticationType">use for create ClaimsIdentity. google->"claimsidentity authenticationtype"</param>
        /// <returns></returns>
        ClaimsIdentity GetIdentity(IJWTUser jwtUser, string authenticationType);

        List<Claim> GetIdentityForRefresh(IJWTUser jwtUser);

        string GetIdFromClaims(ClaimsPrincipal claims);
        string GetIdFromClaims(IEnumerable<Claim> claims);


    }
}