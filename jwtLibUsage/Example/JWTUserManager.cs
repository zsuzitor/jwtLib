using System.Collections.Generic;
using System.Linq;
using jwtLib.JWTAuth.Interfaces;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Diagnostics.CodeAnalysis;

namespace jwtLibUsage.Example
{

    public class JWTUserManager : IJWTUserManager
    {
        private readonly DataBase _db;
        private readonly IJWTHasher _hasher;


        private readonly string _userIdClaimName = "user_id";

        public JWTUserManager(DataBase db, IJWTHasher hasher)
        {
            _db = db;
            _hasher = hasher;
        }


        public async Task<bool> DeleteRefreshTokenHashFromUserAsync([NotNull] string userId, [NotNull] string refreshTokenHash)
        {
            var user = _db.Users.FirstOrDefault(x1 => x1.Id == userId && x1.RefreshTokenHash == refreshTokenHash);
            if (user == null)
                return false;
            user.RefreshTokenHash = null;
            return true;
        }

        public async Task<bool> DeleteRefreshTokenFromUserAsync([NotNull] string userId, [NotNull] string refreshToken)
        {
            var tokenHash = _hasher.GetHash(refreshToken);
            return await DeleteRefreshTokenHashFromUserAsync(userId, tokenHash);
        }


        public async Task<ClaimsIdentity> GetIdentityAsync([NotNull] IJWTUser user, [NotNull] string authenticationType)
        {
            if (user == null)
                return null;

            var claims = new List<Claim>
            {
                new Claim(type: _userIdClaimName,
                    value: await GetUserIdAsync(user)),
                //new Claim(type:ClaimTypes.Name,value:user.UserName)//,
                new Claim(type: ClaimsIdentity.DefaultRoleClaimType, value: "testRole")
            };
            ClaimsIdentity claimsIdentity =
                new ClaimsIdentity(claims, authenticationType, ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
            return claimsIdentity;
        }

        public async Task<List<Claim>> GetIdentityForRefreshAsync([NotNull] IJWTUser jwtUser)
        {
            return new List<Claim>()
            {
                new Claim(_userIdClaimName, await GetUserIdAsync(jwtUser))
            };
        }

        public async Task<bool> ItIsUserClaimsAsync([NotNull] IEnumerable<Claim> claims, [NotNull] IJWTUser jwtUser)
        {
            var userId = await GetUserIdAsync(jwtUser);

            return await ItIsUserClaimsAsync(claims, userId);
        }

        public async Task<bool> ItIsUserClaimsAsync([NotNull] IEnumerable<Claim> claims, [NotNull] string userId)
        {
            var claimId = claims.FirstOrDefault(x => x.Type == _userIdClaimName);
            if (claimId == null)
            {
                return false;
            }

            if (userId != claimId.Value)
            {
                return false;
            }

            return true;
        }

        public async Task<string> GetIdFromClaimsAsync([NotNull] ClaimsPrincipal claims)
        {
            return await GetIdFromClaimsAsync(claims.Claims);

        }

        public async Task<string> GetIdFromClaimsAsync([NotNull] IEnumerable<Claim> claims)
        {
            //ClaimsIdentity.DefaultNameClaimType
            return claims.FirstOrDefault(x1 => x1.Type == _userIdClaimName)?.Value;
        }


        public async Task<string> GetUserIdAsync([NotNull] IJWTUser jwtUser)
        {
            var user = jwtUser as User;
            return user?.Id;
        }

        public async Task<IJWTUser> GetWithRefreshTokenAsync([NotNull] string userId, [NotNull] string refreshToken)
        {
            var tokenHash = _hasher.GetHash(refreshToken);
            return await GetWithRefreshTokenHashAsync(userId, tokenHash);
        }

        public async Task<IJWTUser> GetWithRefreshTokenHashAsync([NotNull] string userId, [NotNull] string refreshTokenHash)
        {
            return _db.Users.FirstOrDefault(x1 => x1.Id == userId && x1.RefreshTokenHash == refreshTokenHash);
        }


        public async Task<bool> SetRefreshTokenAsync([NotNull] IJWTUser jwtUser, [NotNull] string refreshToken)
        {
            var tokenHash = _hasher.GetHash(refreshToken);
            return await SetRefreshTokenHashAsync(jwtUser, tokenHash);
        }

        public async Task<bool> SetRefreshTokenHashAsync([NotNull] IJWTUser jwtUser, [NotNull] string refreshTokenHash)
        {
            var user = jwtUser as User;
            if (user == null)
            {
                return false;
            }

            var userFromDb = _db.Users.FirstOrDefault(x1 => x1.Id == user.Id);
            if (userFromDb == null)
            {
                return false;
            }

            userFromDb.RefreshTokenHash = refreshTokenHash;

            return true;
        }
    }
}