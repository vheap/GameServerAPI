using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    public class JwtService
    {
        private readonly IConfiguration _config;
        private readonly IMemoryCache _cache;
        private readonly byte[] _key;

        public JwtService(IConfiguration config, IMemoryCache cache)
        {
            _config = config;
            _cache = cache;
            _key = Convert.FromBase64String(_config["Jwt:Secret"]);
        }

        public (string AccessToken, string RefreshToken) GenerateTokens(string userId, string username)
        {
            var accessToken = GenerateJwtToken(userId, username, TimeSpan.FromMinutes(15));
            var refreshToken = GenerateRefreshToken();
            _cache.Set(refreshToken, userId, TimeSpan.FromDays(7)); // Store refresh token in cache
            return (accessToken, refreshToken);
        }

        public string? RefreshAccessToken(string refreshToken)
        {
            if (_cache.TryGetValue(refreshToken, out string? userId) && userId != null)
            {
                _cache.Remove(refreshToken);
                var newRefreshToken = GenerateRefreshToken();
                _cache.Set(newRefreshToken, userId, TimeSpan.FromDays(7));
                return GenerateJwtToken(userId, "", TimeSpan.FromMinutes(15));
            }
            return null;
        }

        private string GenerateJwtToken(string userId, string username, TimeSpan duration)
        {
            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim(JwtRegisteredClaimNames.UniqueName, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.Add(duration),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}

