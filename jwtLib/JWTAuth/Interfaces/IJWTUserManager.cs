
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Threading.Tasks;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTUserManager
    {
        string GetUserId([NotNull] IJWTUser jwtUser);
        //Task<IJWTUser> GetUserAsync(string username, string password);

        bool ItIsUserClaims([NotNull] IEnumerable<Claim> claims, [NotNull] IJWTUser jwtUser);
        bool ItIsUserClaims([NotNull] IEnumerable<Claim> claims, [NotNull] string userId);

        Task<IJWTUser> GetWithRefreshTokenAsync([NotNull] string userId, [NotNull] string refreshToken);

        /// <summary>
        /// without validation, only set new token
        /// </summary>
        /// <param name="jwtUser"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        Task<bool> SetRefreshTokenAsync([NotNull] IJWTUser jwtUser, [NotNull] string refreshToken);


        Task<bool> DeleteRefreshTokenFromUserAsync([NotNull] string userId, [NotNull] string refreshToken);

        /// <summary>
        /// get data which will be saved in token
        /// </summary>
        /// <param name="jwtUser"></param>
        /// <param name="authenticationType">use for create ClaimsIdentity. google->"claimsidentity authenticationtype"</param>
        /// <returns></returns>
        ClaimsIdentity GetIdentity([NotNull] IJWTUser jwtUser, [NotNull] string authenticationType);

        List<Claim> GetIdentityForRefresh([NotNull] IJWTUser jwtUser);

        string GetIdFromClaims([NotNull] ClaimsPrincipal claims);
        string GetIdFromClaims([NotNull] IEnumerable<Claim> claims);


    }
}