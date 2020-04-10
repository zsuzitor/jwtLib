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

        /// <summary>
        /// refresh main token
        /// please check old main token status, for that you can invoke "GetCurrentDataFromToken" method.
        /// good status only: "Good" or "ExpiredToken"
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public async Task<AllTokens> Refresh([NotNull] string userId, [NotNull] string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(refreshToken))
                return null;

            string hashOldToken = _hasher.GetHashRefreshToken(refreshToken);
            var user = await _JWTUserManager.GetWithRefreshTokenAsync(userId, hashOldToken);
            if (user == null)
                return null;

            return await Refresh(user);
        }


        /// <summary>
        /// refresh(or create) tokens,
        /// validate user email-password or email-refreshToken before invoke this method
        /// if you have old tokens,
        /// please check old main token status, for that you can invoke "GetCurrentDataFromToken" method.
        /// good status only: "Good" or "ExpiredToken"
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public async Task<AllTokens> Refresh([NotNull] IJWTUser user)
        {
            if (user == null)
                return null;

            string refToken = _tokenHandler.GenerateRefreshToken();
            string refTokenHash = _hasher.GetHashRefreshToken(refToken);
            await _JWTUserManager.SetRefreshTokenAsync(user, refTokenHash);

            var identity = await _JWTUserManager.GetIdentityAsync(user, _settings.TokenName);
            if (identity == null)
                return null;

            return new AllTokens()
            {
                Token = _tokenHandler.GenerateMainToken(identity),
                RefreshToken = refToken
            };
        }

        /// <summary>
        /// encode token, get data from token and token status
        /// return token data only for AuthorizeStatus.Good and AuthorizeStatus.ExpiredToken status
        /// </summary>
        /// <param name="authorizationToken"></param>
        /// <returns></returns>
        public async Task<TokenData> GetCurrentDataFromToken([NotNull] string authorizationToken)
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

                if (claims == null)
                    throw new Exception($"error when {nameof(_tokenHandler.GetClaimsFromToken)} return null");

                res.UserId = await _JWTUserManager.GetIdFromClaimsAsync(claims);

                if (res.UserId == null)
                    throw new Exception($"error when {nameof(_JWTUserManager.GetIdFromClaimsAsync)} return null");

                res.Claims = claims.Claims?.ToList();
                return res;
            }
            catch (SecurityTokenExpiredException) //expired
            {
                res.Status = AuthorizeStatus.ExpiredToken;
                var token = _tokenHandler.DecodeToken(authorizationToken);
                res.UserId = await _JWTUserManager.GetIdFromClaimsAsync(token.Claims);
                res.Claims = token.Claims.ToList();
                return res;
            }
            catch (SecurityTokenValidationException) //changed\broken\bad
            {
                res.Status = AuthorizeStatus.BadToken;
            }
            catch (Exception e) //some error
            {
                res.Status = AuthorizeStatus.ErrorWithDecode;
                res.ErrorsList.Add(e.ToString());
            }

            return null;
        }


        /// <summary>
        /// remove refresh token from user data
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public async Task DeleteRefreshTokenFromUser([NotNull] string userId, [NotNull] string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(refreshToken))
                return;

            string refreshTokenHash = _hasher.GetHashRefreshToken(refreshToken);
            await _JWTUserManager.DeleteRefreshTokenFromUserAsync(userId, refreshTokenHash);
        }

        public string GenerateRefreshToken()
        {
            return _tokenHandler.GenerateRefreshToken();
        }

    }
}