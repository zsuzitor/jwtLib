using jwtLib.JWTAuth.Interfaces;

namespace jwtLib.Example
{
    public class User : IJWTUser
    {
        public string Id { get; set; }
        public string HashPassword { get; set; }
        public string RefreshTokenHash { get; set; }
        public string UserName { get; set; }
    }
}