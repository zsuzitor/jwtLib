using System;
using System.Diagnostics.CodeAnalysis;

namespace jwtLib.JWTAuth.Interfaces
{
    public interface IJWTHasher
    {
        //string GetHash(string token);

        byte[] GenerateSalt();
        byte[] GenerateSalt(string key);

        /// <summary>
        /// хеш с солью
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        string GetSecuredHash(string data);
        bool VerifySaltHash(string data, string storedHash);


        string GetHash(string data, byte[] salt);

        [Obsolete]
        string GetHash(string data, string key = "secret");

        //string GetKeyHash(string token, string key);
        //bool VerifyKeyHash(string token, string storedHash);
    }
}