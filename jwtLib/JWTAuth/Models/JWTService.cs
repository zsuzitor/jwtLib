using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using jwtLib.Exceptions;
using jwtLib.JWTAuth.Enums;
using jwtLib.JWTAuth.Interfaces;
using jwtLib.JWTAuth.Models.Poco;
using Microsoft.IdentityModel.Tokens;

namespace jwtLib.JWTAuth.Models
{
    /// <summary>
    /// inherit this class and add new method if need
    /// </summary>
    public class JWTService : IJWTService
    {
        private readonly IJWTUserManager _JWTUserManager;

        private readonly IJWTServiceSettings _settings;

        //private IJWTHasher _hasher;
        private readonly ITokenHandler _tokenHandler;


        public JWTService(IJWTUserManager JWTUserManager, IJWTServiceSettings settings,
            ITokenHandler tokenHandler)
        {
            _JWTUserManager = JWTUserManager;
            _settings = settings;

            _tokenHandler = tokenHandler;
        }

        /// <summary>
        /// validate refresh token and create\set new tokens
        /// please check old access token status, for that you can invoke "GetCurrentDataFromToken" or "GetUserIdFromAccessTokenIfCan" method.
        /// good status only: "Good" or "ExpiredToken"
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public virtual async Task<AllTokens> RefreshAsync([NotNull] string userId, [NotNull] string oldRefreshToken)
        {
            if (!ValidateRefreshToken(userId, oldRefreshToken))
            {
                throw new JwtAuthNotValideRefreshToken();
            }

            var user = await _JWTUserManager.GetWithRefreshTokenAsync(userId, oldRefreshToken);
            if (user == null)
            {
                throw new JwtAuthUserNotFound();
            }

            return await CreateAndSetNewTokensAsync(user);
        }


        /// <summary>
        /// create and set refresh token without valication and get new tokens,
        /// validate user email-password or email-refreshToken before invoke this method
        /// if you have old tokens,
        /// please check old access token status, for that you can invoke "GetCurrentDataFromToken"  or "GetUserIdFromAccessTokenIfCan" method.
        /// good status only: "Good" or "ExpiredToken"
        /// your can invoke other overload "Refresh" method for validation
        /// 
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual async Task<AllTokens> CreateAndSetNewTokensAsync([NotNull] IJWTUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException();
            }

            var identity = _JWTUserManager.GetIdentity(user, _settings.AuthenticationType);
            if (identity == null)
            {
                throw new JwtAuthIdentityDataIsBad();
            }

            string refToken = GenerateRefreshToken(identity);
            //string refTokenHash = _hasher.GetHashRefreshToken(refToken);
            if (!await _JWTUserManager.SetRefreshTokenAsync(user, refToken))
            {
                throw new JwtAuthCantSetRefreshToken();
            }

            string accessToken = _tokenHandler.GenerateToken(
                identity, _settings.LifetimeAccessToken, _settings.KeyForAccessToken);

            return new AllTokens()
            {
                AccessToken = accessToken,
                RefreshToken = refToken
            };
        }

        /// <summary>
        /// encode token, get data from token and token status
        /// return token data only for AuthorizeStatus.Good and AuthorizeStatus.ExpiredToken status
        /// check ErrorsList collection
        /// </summary>
        /// <param name="authorizationToken"></param>
        /// <returns></returns>
        public virtual TokenData GetCurrentDataFromToken([NotNull] string authorizationToken, [NotNull] string key)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(authorizationToken) || string.IsNullOrWhiteSpace(key))
                    throw new ArgumentNullException();

                TokenData res = new TokenData
                {
                    Status = AuthorizeStatus.ErrorWithDecode
                };

                var claimsObj = _tokenHandler.GetClaimsFromToken(authorizationToken, key, out _);
                var claims = claimsObj?.Claims?.ToList();


                if (claims == null || claims.Count == 0)
                    throw new JwtAuthIdentityDataIsBad($"error when {nameof(_tokenHandler.GetClaimsFromToken)} return null");

                res.UserId = _JWTUserManager.GetIdFromClaims(claims);

                if (string.IsNullOrWhiteSpace(res.UserId))
                    throw new JwtAuthIdentityDataIsBad($"error when {nameof(_JWTUserManager.GetIdFromClaims)} return null");

                res.Claims = claims;
                res.Status = AuthorizeStatus.Good;
                return res;
            }
            catch (SecurityTokenExpiredException) //expired
            {
                var res = new TokenData
                {
                    Status = AuthorizeStatus.ExpiredToken,
                };

                var token = _tokenHandler.DecodeToken(authorizationToken);
                res.UserId = _JWTUserManager.GetIdFromClaims(token.Claims);
                res.Claims = token.Claims.ToList();


            }
            catch (SecurityTokenValidationException) //changed\broken\bad
            {
                var res = new TokenData
                {
                    Status = AuthorizeStatus.BadToken,
                };

                return res;
            }
            catch (Exception e) //some error
            {
                var res = new TokenData
                {
                    Status = AuthorizeStatus.ErrorWithDecode,
                };

                res.ErrorsList.Add(e.Message);
                return res;
            }

            return null;
        }


        /// <summary>
        /// remove refresh token from user data
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public virtual async Task<bool> DeleteRefreshTokenFromUserAsync([NotNull] string userId, [NotNull] string refreshToken)
        {
            if (!ValidateRefreshToken(userId, refreshToken))
            {
                return false;
            }

            return await _JWTUserManager.DeleteRefreshTokenFromUserAsync(userId, refreshToken);
        }

        public virtual string GenerateRefreshToken([NotNull] IJWTUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException();
            }

            var identity = _JWTUserManager.GetIdentity(user, _settings.AuthenticationType);
            if (identity == null)
                throw new JwtAuthIdentityDataIsBad();

            return GenerateRefreshToken(identity);
        }


        /// <summary>
        /// 
        /// 
        /// </summary>
        /// <param name="identity"></param>
        /// <returns></returns>
        public virtual string GenerateRefreshToken([NotNull] ClaimsIdentity identity)
        {
            if (identity == null)
            {
                throw new JwtAuthIdentityDataIsBad();
            }

            return _tokenHandler.GenerateToken(
                identity, _settings.LifetimeRefreshToken, _settings.KeyForRefreshToken);
        }


        public virtual ClaimsPrincipal GetClaimsFromAccessToken([NotNull] string authorizationToken, out SecurityToken tokenSecure)
        {
            var claims = _tokenHandler.GetClaimsFromToken(authorizationToken, _settings.KeyForAccessToken, out tokenSecure);
            if (claims == null)
            {
                throw new JwtAuthIdentityDataIsBad();
            }

            return claims;
        }

        public virtual ClaimsPrincipal GetClaimsFromRefreshToken([NotNull] string authorizationToken, out SecurityToken tokenSecure)
        {
            var claims = _tokenHandler.GetClaimsFromToken(authorizationToken, _settings.KeyForRefreshToken, out tokenSecure);
            if (claims == null)
            {
                throw new JwtAuthIdentityDataIsBad();
            }

            return claims;
        }

        /// <summary>
        /// 
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public virtual bool ValidateRefreshToken([NotNull] string userId, [NotNull] string refreshToken)//todo exception
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(refreshToken))
            {
                throw new ArgumentNullException();
            }

            var decoded = GetCurrentDataFromToken(refreshToken, _settings.KeyForRefreshToken);
            if (decoded?.Status != AuthorizeStatus.Good)
            {
                throw new JwtAuthNotValideRefreshToken();
            }

            var successCompare = _JWTUserManager.ItIsUserClaims(decoded.Claims, userId);

            if (!successCompare)
            {
                throw new JwtAuthIdentityDataIsBad();
            }

            return true;
        }

        public virtual string GetUserIdFromRefreshToken([NotNull] string refreshToken)
        {
            var decoded = GetCurrentDataFromToken(refreshToken, _settings.KeyForRefreshToken);
            if (decoded?.Status != AuthorizeStatus.Good)
            {
                throw new JwtAuthTokenNotInGoodStatus();
            }

            var userId = _JWTUserManager.GetIdFromClaims(decoded.Claims);
            if (string.IsNullOrWhiteSpace(userId))
            {
                throw new JwtAuthCantGetUserId();
            }

            return userId;
        }

        /// <summary>
        /// only AuthorizeStatus.Good status
        /// </summary>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        public virtual string GetUserIdFromAccessToken([NotNull] string accessToken)
        {
            var decoded = GetCurrentDataFromToken(accessToken, _settings.KeyForAccessToken);
            if (decoded?.Status != AuthorizeStatus.Good)
            {
                throw new JwtAuthTokenNotInGoodStatus();
            }

            string userId = _JWTUserManager.GetIdFromClaims(decoded.Claims);
            if (string.IsNullOrWhiteSpace(userId))
            {
                throw new JwtAuthCantGetUserId();
            }

            return userId;
        }

        /// <summary>
        /// token in AuthorizeStatus.Good and AuthorizeStatus.ExpiredToken status
        /// can throw exc!
        /// </summary>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        public virtual string GetUserIdFromAccessTokenIfCan([NotNull] string accessToken)
        {
            var decoded = GetCurrentDataFromToken(accessToken, _settings.KeyForAccessToken);
            if (decoded == null || (decoded.Status != AuthorizeStatus.Good && decoded.Status != AuthorizeStatus.ExpiredToken))
            {
                return null;//todo
            }

            string userId = _JWTUserManager.GetIdFromClaims(decoded.Claims);
            if (string.IsNullOrWhiteSpace(userId))
            {
                throw new JwtAuthCantGetUserId();
            }

            return userId;
        }

        public virtual async Task<IJWTUser> GetUserByRefreshTokenAsync([NotNull] string userId, [NotNull] string refreshToken)
        {
            if (!ValidateRefreshToken(userId, refreshToken))
            {
                throw new JwtAuthNotValideRefreshToken();
            }

            var user = await _JWTUserManager.GetWithRefreshTokenAsync(userId, refreshToken);

            //if (user == null)
            //{
            //    throw new JwtAuthUserNotFound();
            //}

            return user;

        }

        public virtual async Task<IJWTUser> GeUserByAccessTokenAsync([NotNull] string accessToken)
        {
            var userId = GetUserIdFromAccessToken(accessToken);

            var user = await _JWTUserManager.GetUserById(userId);
            //if (user == null)
            //{
            //    throw new JwtAuthUserNotFound();
            //}
            return user;

        }

    }
}