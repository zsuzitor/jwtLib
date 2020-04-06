namespace jwtLib.JWTAuth.Enums
{
    public enum AuthorizeStatus
    {
        Good,
        ExpiredToken,
        BadToken,
        ErrorWithDecode,
    }
}