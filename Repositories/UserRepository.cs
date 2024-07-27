using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using KYC_apllication_2.Data;
using KYC_apllication_2.DTOs;
using KYC_apllication_2.Entity;

namespace KYC_apllication_2.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly KYCContext _context;
        private readonly IConfiguration _configuration;

        public UserRepository(KYCContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<bool> ValidateUserCredentialsAsync(string username, string password)
        {
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);

            if (user == null) return false;

            var passwordHash = ComputeSha256Hash(password);
            return user.Password.Equals(passwordHash, StringComparison.OrdinalIgnoreCase);
        }

        public async Task<string> GenerateJwtTokenAsync(string username)
        {
            // Retrieve the user from the database
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);
            if (user == null)
            {
                return null; // User not found
            }

            // Retrieve and validate the JWT key from configuration
            var keyString = _configuration["Jwt:Key"];
            if (string.IsNullOrWhiteSpace(keyString))
            {
                throw new ArgumentException("JWT key is not configured.");
            }

            var key = Encoding.UTF8.GetBytes(keyString);
            if (key.Length < 32)
            {
                throw new ArgumentException("Key length is less than 256 bits (32 characters). Ensure the key is at least 32 characters long.");
            }

            var symmetricSecurityKey = new SymmetricSecurityKey(key);
            var tokenHandler = new JwtSecurityTokenHandler();

            // Retrieve and validate the expiration time
            if (!double.TryParse(_configuration["Jwt:ExpireMinutes"], out var expireMinutes))
            {
                throw new ArgumentException("Invalid JWT expiration time configured.");
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
                Expires = DateTime.UtcNow.AddMinutes(expireMinutes),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public async Task<bool> RegisterUserAsync(UserRegisterDto user)
        {
            var newUser = new User
            {
                Username = user.Username,
                Password = ComputeSha256Hash(user.Password),
                Role = user.Role,
                Email = user.Email  // Ensure this is correctly set
            };

            await _context.Users.AddAsync(newUser);
            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<bool> UpdateAdminProfileAsync(AdminProfileDto adminProfileDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(u => u.UserId == adminProfileDto.AdminId);

            if (user == null) return false;

            user.Username = adminProfileDto.Username;
            user.Email = adminProfileDto.Email;

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<bool> ChangeAdminPasswordAsync(ChangePasswordDto changePasswordDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(u => u.UserId == changePasswordDto.UserId);

            if (user == null) return false;

            var oldPasswordHash = ComputeSha256Hash(changePasswordDto.OldPassword);
            if (!user.Password.Equals(oldPasswordHash, StringComparison.OrdinalIgnoreCase)) return false;

            user.Password = ComputeSha256Hash(changePasswordDto.NewPassword);

            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return true;
        }

        private string ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}