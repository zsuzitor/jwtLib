using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using jwtLib.JWTAuth.Enums;
using jwtLib.JWTAuth.Interfaces;
using jwtLib.JWTAuth.Models.Poco;
using Microsoft.IdentityModel.Tokens;

namespace jwtLib.JWTAuth.Models
{
    public class JWTService : IJWTService
    {
        private IJWTUserManager _JWTUserManager;
        private IJWTSettings _settings;
        private IJWTHasher _hasher;
        private ITokenHandler _tokenHandler;

        public JWTService(IJWTUserManager JWTUserManager, IJWTSettings settings, IJWTHasher hasher,
            ITokenHandler tokenHandler)
        {
            _JWTUserManager = JWTUserManager;
            _settings = settings;
            _hasher = hasher;
            _tokenHandler = tokenHandler;
        }


        public async Task<AllTokens> Refresh([NotNull] string userId, [NotNull] string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(refreshToken))
                return null;

            string hashOldToken = _hasher.GetHashRefreshToken(refreshToken);
            var user = await _JWTUserManager.GetWithRefreshTokenAsync(userId, hashOldToken);
            if (user == null)
                return null;

            string newToken = _tokenHandler.GenerateRefreshToken();
            string newTokenHash = _hasher.GetHashRefreshToken(newToken);
            await _JWTUserManager.SetRefreshTokenAsync(user, newTokenHash);

            return new AllTokens()
            {
                Token = _tokenHandler.GenerateMainToken(
                    await _JWTUserManager.GetIdentityAsync(user, _settings.TokenName)),
                RefreshToken = newToken
            };
        }


        public async Task<AllTokens> Refresh(IJWTUser user)
        {
            if (user == null)
                return null;

            string refToken = _tokenHandler.GenerateRefreshToken();
            string refTokenHash = _hasher.GetHashRefreshToken(refToken);
            await _JWTUserManager.SetRefreshTokenAsync(user, refTokenHash);

            return new AllTokens()
            {
                Token = _tokenHandler.GenerateMainToken(
                    await _JWTUserManager.GetIdentityAsync(user, _settings.TokenName)),
                RefreshToken = refToken
            };
        }


        public async Task<TokenData> GetCurrentIdFromToken([NotNull] string authorizationToken)
        {
            if (string.IsNullOrWhiteSpace(authorizationToken))
                return null;

            TokenData res = new TokenData
            {
                Status = AuthorizeStatus.Good
            };

            try
            {
                var claims = _tokenHandler.GetClaimsFromToken(authorizationToken, out SecurityToken token);
                res.UserId = await _JWTUserManager.GetIdFromClaimsAsync(claims);
                res.Claims = claims.Claims.ToList();
                return res;
            }
            catch (SecurityTokenExpiredException) //просрочен
            {
                res.Status = AuthorizeStatus.ExpiredToken;
                var token = _tokenHandler.DecodeToken(authorizationToken);
                res.UserId = await _JWTUserManager.GetIdFromClaimsAsync(token.Claims);
                res.Claims = token.Claims.ToList();
                return res;
            }
            catch (SecurityTokenValidationException) //изменен извне(\поломан\недопустим)
            {
                res.Status = AuthorizeStatus.BadToken;
            }
            catch (Exception) //все остальное
            {
                res.Status = AuthorizeStatus.ErrorWithDecode;
            }

            return null;
        }


        public async Task DeleteRefreshTokenFromUser([NotNull] string userId, [NotNull] string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(refreshToken))
                return;

            string refreshTokenHash = _hasher.GetHashRefreshToken(refreshToken);
            await _JWTUserManager.DeleteRefreshTokenFromUserAsync(userId, refreshTokenHash);
        }
    }
}