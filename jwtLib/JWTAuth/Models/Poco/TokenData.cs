using System.Collections.Generic;
using System.Security.Claims;
using jwtLib.JWTAuth.Enums;

namespace jwtLib.JWTAuth.Models.Poco
{
    public class TokenData
    {
        public string UserId { get; set; }
        public AuthorizeStatus Status { get; set; }
        public List<string> ErrorsList { get; set; }
        public List<Claim> Claims { get; set; }

        public TokenData()
        {
            ErrorsList = new List<string>();
            Claims = new List<Claim>();
        }
    }
}