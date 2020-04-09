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

        public JWTUserManager(DataBase db)
        {
            _db = db;
        }


        public async Task DeleteRefreshTokenFromUserAsync(string userId, string refreshTokenHash)
        {
            var user = _db.Users.FirstOrDefault(x1 => x1.Id == userId && x1.RefreshTokenHash == refreshTokenHash);
            if (user == null)
                return;
            user.RefreshTokenHash = null;
        }


        public async Task<ClaimsIdentity> GetIdentityAsync(IJWTUser user, string authenticationType)
        {
            if (user == null)
                return null;

            var claims = new List<Claim>
            {
                new Claim(type: ClaimsIdentity.DefaultNameClaimType,
                    value: await this.GetUserIdAsync(user)),
                //new Claim(type:ClaimTypes.Name,value:user.UserName)//,
                new Claim(type: ClaimsIdentity.DefaultRoleClaimType, value: "testRole")
            };
            ClaimsIdentity claimsIdentity =
                new ClaimsIdentity(claims, authenticationType, ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
            return claimsIdentity;
        }


        public async Task<string> GetIdFromClaimsAsync(ClaimsPrincipal claims)
        {
            return claims?.Identity?.Name;
        }

        public async Task<string> GetIdFromClaimsAsync(IEnumerable<Claim> claims)
        {
            return claims.FirstOrDefault(x1 => x1.Type == ClaimsIdentity.DefaultNameClaimType)?.Value;
        }


        public async Task<string> GetUserIdAsync(IJWTUser jwtUser)
        {
            var user = jwtUser as User;
            return user?.Id;
        }

        public async Task<IJWTUser> GetWithRefreshTokenAsync(string userId, string refreshTokenHash)
        {
            return _db.Users.FirstOrDefault(x1 => x1.Id == userId && x1.RefreshTokenHash == refreshTokenHash);
        }


        public async Task SetRefreshTokenAsync(IJWTUser jwtUser, string refreshTokenHash)
        {
            var user = jwtUser as User;
            var userFromDb = _db.Users.FirstOrDefault(x1 => x1.Id == user.Id);
            userFromDb.RefreshTokenHash = refreshTokenHash;
        }
    }
}