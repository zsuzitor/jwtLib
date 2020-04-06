using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using jwtLib.JWTAuth.Interfaces;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace jwtLib.JWTAuth.Models
{
    public class JWTTokenHandler : ITokenHandler
    {
        private IJWTSettings _settings;

        public JWTTokenHandler(IJWTSettings settings)
        {
            _settings = settings;
        }

        public SymmetricSecurityKey GetSymmetricSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_settings.Key));
        }

        public string GenerateMainToken(ClaimsIdentity identity)
        {
            var now = DateTime.UtcNow;
            // создаем JWT-токен
            var jwt = new JwtSecurityToken(
                issuer: _settings.Issuer,
                audience: _settings.Audience,
                notBefore: now,
                claims: identity?.Claims,
                expires: now.Add(TimeSpan.FromMinutes(_settings.Lfetime)),
                signingCredentials: new SigningCredentials(this.GetSymmetricSecurityKey(),
                    SecurityAlgorithms.HmacSha256));
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        public string GenerateRefreshToken()
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, _settings.LengthRefreshToken)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public ClaimsPrincipal GetClaimsFromToken(string authorizationToken, out SecurityToken tokenSecure)
        {
            //tokenSecure = null;
            var key = Encoding.ASCII.GetBytes(_settings.Key);
            var handler = new JwtSecurityTokenHandler();
            var validations = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false
            };
            return handler.ValidateToken(authorizationToken, validations, out tokenSecure);
        }

        public JwtSecurityToken DecodeToken(string token)
        {
            return new JwtSecurityTokenHandler().ReadJwtToken(token);
        }
    }
}