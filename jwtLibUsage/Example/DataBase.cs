using System.Collections.Generic;

namespace jwtLib.Example
{
    public class DataBase
    {
        public List<User> Users { get; set; }

        public DataBase()
        {
            Users = new List<User>();
        }
    }
}