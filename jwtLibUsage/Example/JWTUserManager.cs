using System.Collections.Generic;
using System.Linq;
using jwtLib.JWTAuth.Interfaces;
using System.Security.Claims;
using System.Threading.Tasks;

namespace jwtLibUsage.Example
{

    public class JWTUserManager : IJWTUserManager
    {
        private DataBase _db;
        private IJWTHasher _hasher;


        private string _userIdClaimName = "user_id";

        public JWTUserManager(DataBase db, IJWTHasher hasher)
        {
            _db = db;
            _hasher = hasher;
        }


        public async Task DeleteRefreshTokenHashFromUserAsync(string userId, string refreshTokenHash)
        {
            var user = _db.Users.FirstOrDefault(x1 => x1.Id == userId && x1.RefreshTokenHash == refreshTokenHash);
            if (user == null)
                return;
            user.RefreshTokenHash = null;
        }

        public async Task DeleteRefreshTokenFromUserAsync(string userId, string refreshToken)
        {
            var tokenHash = _hasher.GetHash(refreshToken);
            await DeleteRefreshTokenHashFromUserAsync(userId, tokenHash);
        }


        public async Task<ClaimsIdentity> GetIdentityAsync(IJWTUser user, string authenticationType)
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

        public async Task<List<Claim>> GetIdentityForRefreshAsync(IJWTUser jwtUser)
        {
            return new List<Claim>()
            {
                new Claim(_userIdClaimName, await GetUserIdAsync(jwtUser))
            };
        }

        public async Task<bool> ItIsUserClaims(List<Claim> claims, IJWTUser jwtUser)
        {
            var userId = await GetUserIdAsync(jwtUser);

            return await ItIsUserClaims(claims, userId);
        }

        public async Task<bool> ItIsUserClaims(List<Claim> claims, string userId)
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

        public async Task<string> GetIdFromClaimsAsync(ClaimsPrincipal claims)
        {
            return await GetIdFromClaimsAsync(claims.Claims);
            //var g_= claims?.Claims.ToList();
            //return claims?.Identity?.Name;
        }

        public async Task<string> GetIdFromClaimsAsync(IEnumerable<Claim> claims)
        {
            //ClaimsIdentity.DefaultNameClaimType
            return claims.FirstOrDefault(x1 => x1.Type == _userIdClaimName)?.Value;
        }


        public async Task<string> GetUserIdAsync(IJWTUser jwtUser)
        {
            var user = jwtUser as User;
            return user?.Id;
        }

        public async Task<IJWTUser> GetWithRefreshTokenAsync(string userId, string refreshToken)
        {
            var tokenHash = _hasher.GetHash(refreshToken);
            return await GetWithRefreshTokenHashAsync(userId, tokenHash);
        }

        public async Task<IJWTUser> GetWithRefreshTokenHashAsync(string userId, string refreshTokenHash)
        {
            return _db.Users.FirstOrDefault(x1 => x1.Id == userId && x1.RefreshTokenHash == refreshTokenHash);
        }


        public async Task SetRefreshTokenAsync(IJWTUser jwtUser, string refreshToken)
        {
            var tokenHash = _hasher.GetHash(refreshToken);
            await SetRefreshTokenHashAsync(jwtUser, tokenHash);
        }

        public async Task SetRefreshTokenHashAsync(IJWTUser jwtUser, string refreshTokenHash)
        {
            var user = jwtUser as User;
            if (user != null)
            {
                return;
            }
            var userFromDb = _db.Users.FirstOrDefault(x1 => x1.Id == user.Id);
            if (userFromDb == null)
            {
                return;
            }
            userFromDb.RefreshTokenHash = refreshTokenHash;
        }
    }
}