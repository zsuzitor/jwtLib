

namespace jwtLib.JWTAuth.Interfaces
{
    /// <summary>
    /// you can not implement this interface in your main user entity,
    /// just implement in a class that will contain data that needs to be stored in a token.
    /// so that you can return userId and all the necessary data to GetIdentityAsync, GetUserIdAsync
    /// </summary>
    public interface IJWTUser
    {
    }
}