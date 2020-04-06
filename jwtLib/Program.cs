using System;
using System.Collections.Generic;
using System.Linq;
using jwtLib.Example;
using jwtLib.JWTAuth.Models;

namespace jwtLib
{
    class Program
    {
        static void Main(string[] args)
        {
            string pshash = "111u".GetHashCode().ToString();

            var db = new DataBase()
            {
                Users = new List<User>()
                {
                    new User()
                    {
                        Id = "1", UserName = "u1", HashPassword = pshash, RefreshTokenHash = null
                    },
                    new User()
                    {
                        Id = "2", UserName = "u2", HashPassword = pshash, RefreshTokenHash = null
                    },
                    new User()
                    {
                        Id = "3", UserName = "u3", HashPassword = pshash, RefreshTokenHash = null
                    },
                    new User()
                    {
                        Id = "4", UserName = "u4", HashPassword = pshash, RefreshTokenHash = null
                    },
                    new User()
                    {
                        Id = "5", UserName = "u5", HashPassword = pshash, RefreshTokenHash = null
                    },
                }
            };


            var _JWTService = new JWTService(new JWTUserManager(db), new JWTSettings(),
                new JWTHasher(), new JWTTokenHandler(new JWTSettings()));

            var user1 = db.Users.FirstOrDefault(x1 => x1.Id == "1");
            var tokens = _JWTService.Refresh(user1).Result;
            var id = _JWTService.GetCurrentIdFromToken(tokens.Token).Result;
            var newTokens = _JWTService.Refresh(user1.Id, tokens.RefreshToken).Result;
            _JWTService.DeleteRefreshTokenFromUser("1", newTokens.RefreshToken).Wait();

            Console.WriteLine("Hello World!");
        }
    }
}
