using jwtLib.JWTAuth.Interfaces;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;
using System.Text;

namespace jwtLib.JWTAuth.Models
{
    public class JWTHasher : IJWTHasher
    {
        private const int SaltSize = 128 / 8; // 16 bytes
        private const int HashSize = 256 / 8; // 32 bytes
        private const int IterationCount = 10000;

        public byte[] GenerateSalt()
        {
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        public byte[] GenerateSalt(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentNullException(nameof(key));

            // Используем сам key для генерации детерминированной соли
            using (var sha256 = SHA256.Create())
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                byte[] hash = sha256.ComputeHash(keyBytes);

                // Обрезаем или расширяем до нужного размера соли
                byte[] salt = new byte[SaltSize];
                Array.Copy(hash, 0, salt, 0, SaltSize);

                return salt;
            }
        }

        public string GetHash(string data, byte[] salt)
        {

            // Derive the hash
            byte[] hash = KeyDerivation.Pbkdf2(
                password: data,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256, // Используйте SHA256 вместо SHA1 для лучшей безопасности
                iterationCount: IterationCount,
                numBytesRequested: HashSize);

            // Combine salt and hash for storage
            byte[] hashBytes = new byte[SaltSize + HashSize];
            Array.Copy(salt, 0, hashBytes, 0, SaltSize);
            Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);

            return Convert.ToBase64String(hashBytes);
        }

        [Obsolete]
        public string GetHash(string data, string key = "secret")
        {
            return GetSecuredHash(data, key);
        }

        /// <summary>
        /// 
        /// exc: ArgumentNullException
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string GetSecuredHash(string data)
        {
            // Generate a random salt
            var salt = GenerateSalt();
            return GetHash(data, salt);
        }

        public string GetSecuredHash(string data, string key)
        {
            var salt = GenerateSalt(key);
            return GetHash(data, salt);
        }


        public bool VerifySaltHash(string data, string storedHash)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new ArgumentNullException(nameof(data));

            if (string.IsNullOrWhiteSpace(storedHash))
                throw new ArgumentNullException(nameof(storedHash));

            // Extract salt and hash from stored value
            byte[] hashBytes = Convert.FromBase64String(storedHash);

            if (hashBytes.Length != SaltSize + HashSize)
                return false;

            byte[] salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            // Compute hash for the provided token
            byte[] expectedHash = KeyDerivation.Pbkdf2(
                password: data,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: IterationCount,
                numBytesRequested: HashSize);

            // Compare in constant time
            return CryptographicOperations.FixedTimeEquals(
                expectedHash,
                hashBytes.AsSpan(SaltSize, HashSize).ToArray());
        }
    }
}