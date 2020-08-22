using System;
using System.IdentityModel.Tokens.Jwt;
using jwtLib.JWTAuth.Interfaces;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace jwtLib.JWTAuth.Models
{
    public class JWTTokenHandler : ITokenHandler
    {
        private readonly IJWTSettings _settings;

        public JWTTokenHandler(IJWTSettings settings)
        {
            _settings = settings;
        }

        public virtual SymmetricSecurityKey GetSymmetricSecurityKey(string key)
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key));
        }

        public virtual string GenerateToken(ClaimsIdentity identity, int lifeTimeInMinute, string key)
        {
            var now = DateTime.UtcNow;
            // create JWT-token
            var jwt = new JwtSecurityToken(
                issuer: _settings.Issuer,
                audience: _settings.Audience,
                notBefore: now,
                claims: identity?.Claims,
                expires: now.Add(TimeSpan.FromMinutes(lifeTimeInMinute)),
                signingCredentials: new SigningCredentials(this.GetSymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256));
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }


        public virtual ClaimsPrincipal GetClaimsFromToken(string authorizationToken, string key, out SecurityToken tokenSecure)
        {
            //tokenSecure = null;
            var keyBytes = Encoding.ASCII.GetBytes(key);
            var handler = new JwtSecurityTokenHandler();
            var validations = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
                ValidateIssuer = false,
                ValidateAudience = false
            };

            return handler.ValidateToken(authorizationToken, validations, out tokenSecure);
        }

        public virtual JwtSecurityToken DecodeToken(string token)
        {
            return new JwtSecurityTokenHandler().ReadJwtToken(token);
        }
    }
}