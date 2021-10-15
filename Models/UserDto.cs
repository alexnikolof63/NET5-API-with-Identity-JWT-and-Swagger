using Net5Auth.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Net5Auth.Models
{
    public class UserDto
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Password { get; internal set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public IList<string> Roles { get; internal set; }
        //public string Token { get; set; }
        //public DateTime? TokenExpires { get; set; }
        //public string RefreshToken { get; set; }

        public UserDto GetUserDto(ApplicationUser usr)
        {
            UserDto dto = new UserDto
            {
                Id = usr.Id,
                UserName = usr.UserName,
                Password = null,
                Email = usr.Email,
                PhoneNumber = usr.PhoneNumber,
            };

            return dto;
        }
    }
}
