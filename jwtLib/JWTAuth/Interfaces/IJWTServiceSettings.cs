namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTServiceSettings
    {

        int LifetimeAccessToken { get; } // life time access token in minutes
        int LifetimeRefreshToken { get; }// life time refresh token in minutes, longer than LifetimeAccessToken

        string KeyForAccessToken { get; } // 
        string KeyForRefreshToken { get; } // 

        string AuthenticationType { get; } // tpye for ClaimsIdentity


    }
}