using Net5Auth.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Net5Auth.Models;
using Microsoft.AspNetCore.Authorization;

namespace Net5Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;

        public AuthenticateController(UserManager<ApplicationUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("token")]
        public async Task<IActionResult> token([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Uri, user.ServiceLink),
                    new Claim(ClaimTypes.Webpage, user.Host),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                var token = GenerateJwtSecurityToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }

        private JwtSecurityToken GenerateJwtSecurityToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            return new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(12),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );
        }
        private string GenerateToken(ApplicationUser user)
        {
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] {
                new Claim(JwtRegisteredClaimNames.NameId, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
                Expires = DateTime.UtcNow.AddHours(12),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
                Issuer = _configuration["JWT:ValidIssuer"],
                Audience = _configuration["JWT:ValidAudience"]
            };
            var token = jwtSecurityTokenHandler.CreateToken(tokenDescriptor);
            return jwtSecurityTokenHandler.WriteToken(token);
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            return await CreateUserAsync(model);
        }

        private async Task<IActionResult> CreateUserAsync(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            var user = new ApplicationUser();
            user.Email = model.Email;
            user.SecurityStamp = Guid.NewGuid().ToString();
            user.UserName = model.Username;
            user.Host = model.Host;
            user.ServiceLink = model.ServiceLink;
            user.IsEnabled = model.IsEnabled;
            user.Notes = model.Notes;

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [Authorize]
        [HttpGet("GetAllUsers")]
        public async Task<IEnumerable<UserDto>> GetAllUsers()
        {

            try
            {
                var users = _userManager.Users;
                List<UserDto> usersDto = new();
                foreach (var usr in users)
                {
                    UserDto dto = new();
                    dto = dto.GetUserDto(usr);
                    usersDto.Add(dto);
                }

                return await Task.FromResult(usersDto);
            }
            catch
            {
                return null;
            }

        }

        [Authorize]
        [HttpGet("GetUserById/{Id}")]
        public async Task<UserDto> GetUserById(string Id)
        {
            try
            {
                var usr = await _userManager.FindByIdAsync(Id);
                UserDto dto = new();
                dto = dto.GetUserDto(usr);
                return await Task.FromResult(dto);
            }
            catch
            {
                return null;
            }

        }

        [Authorize]
        [HttpPut("UpdateUser/{id}")]
        public async Task<IActionResult> UpdateUser(string id, [FromBody] UserDto userDto)
        {
            if (id != userDto.Id)
            {
                return BadRequest();
            }

            try
            {
                var appUser = await _userManager.FindByIdAsync(id);
                var userRoles = await _userManager.GetRolesAsync(appUser);

                appUser.UserName = userDto.UserName;
                appUser.Email = userDto.Email;
                appUser.PhoneNumber = userDto.PhoneNumber;

                await _userManager.UpdateAsync(appUser);

                if (userRoles != userDto.Roles)
                {
                    //Remuve Roles
                    foreach (var role in userRoles)
                    {
                        if (!userDto.Roles.Contains(role))
                            await _userManager.RemoveFromRoleAsync(appUser, role);
                    };

                    //Add Roles
                    foreach (var role in userDto.Roles)
                    {
                        if (!userRoles.Contains(role))
                            await _userManager.AddToRoleAsync(appUser, role);
                    };
                }

                if (!string.IsNullOrEmpty(userDto.Password))
                {
                    await _userManager.RemovePasswordAsync(appUser);
                    await _userManager.AddPasswordAsync(appUser, userDto.Password);
                }

                //var claims = _userManager.GetClaimsAsync(appUser);
                //if (claims.Result.Count > 0 && claims.Result != userDto.Claims)
                //{

                //}

                return NoContent();
            }
            catch
            {
                return null;
            }
        }
    }
}
