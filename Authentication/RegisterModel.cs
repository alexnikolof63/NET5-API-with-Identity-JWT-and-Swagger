using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace Net5Auth.Authentication
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "User Name is required")]
        public string Username { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Host is required")]
        public string Host { get; set; }

        [Required(ErrorMessage = "ServiceLink is required")]
        public string ServiceLink { get; set; }

        [Required(ErrorMessage = "IsEnabled is required")]
        public bool IsEnabled { get; set; }

        public string Notes { get; set; }

    }
}
