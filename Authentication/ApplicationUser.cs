using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Net5Auth.Models;

namespace Net5Auth.Authentication
{
    public class ApplicationUser : IdentityUser
    {
        public string Host { get; set; }
        public string ServiceLink { get; set; }
        public bool? IsEnabled { get; set; }
        public string Notes { get; set; }
        public int? ReleaseId { get; set; }

    }
}
