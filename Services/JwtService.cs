using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApplication1.Configuration;
using WebApplication1.Models;
using WebApplication1.Repositories;

namespace WebApplication1.Services
{
    public class JwtService
    {
        private readonly IConfiguration _config;
        private readonly ILogger<JwtService> _logger;
        private readonly byte[] _key;

        // In‑memory token stores:
        // Maps userId to their current TokenPair.
        private readonly ConcurrentDictionary<string, TokenPair> _userTokens = new ConcurrentDictionary<string, TokenPair>();
        // Maps refresh token string to the corresponding userId.
        private readonly ConcurrentDictionary<string, string> _refreshToUser = new ConcurrentDictionary<string, string>();

        // A lock to synchronize token operations.
        private readonly object _lock = new object();

        public JwtService(IConfiguration config, ILogger<JwtService> logger)
        {
            _config = config;
            _logger = logger;
            _key = Convert.FromBase64String(_config["Jwt:Secret"]);
        }

        /// <summary>
        /// Generates a new access token and refresh token for the given user.
        /// Invalidates any existing tokens for the user to ensure a single login session.
        /// </summary>
        public Task<(string AccessToken, string RefreshToken)> GenerateTokensAsync(string userId, string username)
        {
            lock (_lock)
            {
                // Invalidate any existing tokens for the user.
                if (_userTokens.TryRemove(userId, out var existingPair))
                {
                    _refreshToUser.TryRemove(existingPair.RefreshToken, out _);
                    _logger.LogInformation("Existing tokens for user {UserId} have been invalidated.", userId);
                }

                // Generate new tokens.
                var accessToken = GenerateJwtToken(userId, username, TimeSpan.FromMinutes(15));
                var refreshToken = GenerateRefreshToken();

                var tokenPair = new TokenPair
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                };

                // Store the new tokens in memory.
                _userTokens[userId] = tokenPair;
                Console.WriteLine($"Created new UserID {userId}");
                _refreshToUser[refreshToken] = userId;

                _logger.LogInformation("Generated new tokens for user {UserId}.", userId);
                return Task.FromResult((accessToken, refreshToken));
            }
        }

        /// <summary>
        /// Refreshes the access token (and refresh token) using a valid refresh token.
        /// </summary>
        public Task<(string AccessToken, string RefreshToken)?> RefreshTokensAsync(string refreshToken)
        {
            lock (_lock)
            {
                if (_refreshToUser.TryGetValue(refreshToken, out string userId))
                {
                    // Validate that the stored token pair for the user matches the provided refresh token.
                    if (_userTokens.TryGetValue(userId, out var tokenPair) && tokenPair.RefreshToken == refreshToken)
                    {
                        // Remove old tokens.
                        _userTokens.TryRemove(userId, out _);
                        _refreshToUser.TryRemove(refreshToken, out _);

                        // Generate new tokens.
                        var newAccessToken = GenerateJwtToken(userId, "", TimeSpan.FromMinutes(15)); // Optionally include the username.
                        var newRefreshToken = GenerateRefreshToken();

                        var newTokenPair = new TokenPair
                        {
                            AccessToken = newAccessToken,
                            RefreshToken = newRefreshToken
                        };

                        _userTokens[userId] = newTokenPair;
                        _refreshToUser[newRefreshToken] = userId;

                        _logger.LogInformation("Tokens refreshed for user {UserId}.", userId);
                        return Task.FromResult<(string, string)?>((newAccessToken, newRefreshToken));
                    }
                    else
                    {
                        _logger.LogWarning("Refresh token mismatch for user {UserId}.", userId);
                        return Task.FromResult<(string, string)?>(null);
                    }
                }
                else
                {
                    _logger.LogWarning("Refresh token not found: {RefreshToken}", refreshToken);
                    return Task.FromResult<(string, string)?>(null);
                }
            }
        }

        /// <summary>
        /// Removes all tokens associated with a user, effectively logging them out.
        /// </summary>
        public Task LogoutAsync(string userId)
        {
            lock (_lock)
            {
                _logger.LogCritical($"Remaining tokens before: {_userTokens.Count}");
                if (_userTokens.TryRemove(userId, out var tokenPair))
                {
                    _refreshToUser.TryRemove(tokenPair.RefreshToken, out _);
                    _logger.LogInformation("User {UserId} logged out, tokens removed.", userId);
                    _logger.LogCritical($"Remaining tokens after: {_userTokens.Count}");
                }
                else
                {
                    _logger.LogWarning("Logout attempted for user {UserId} with no active tokens.", userId);
                }
            }
            return Task.CompletedTask;
        }

        // Generates a JWT token with the specified duration.
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
        /// <summary>
        /// Returns the access token and its remaining validity (in minutes) for the given userId, or null if not found.
        /// </summary>
        public Task<(string AccessToken, int RemainingValidityMinutes)?> GetTokenInfoByUserIdAsync(string userId)
        {
            lock (_lock)
            {
                if (_userTokens.TryGetValue(userId, out var tokenPair))
                {
                    var tokenHandler = new JwtSecurityTokenHandler();
                    try
                    {
                        // Parse the token and use the ValidTo property which is automatically set
                        var jwtToken = tokenHandler.ReadJwtToken(tokenPair.AccessToken);
                        int remainingMinutes = (int)Math.Max(0, (jwtToken.ValidTo - DateTime.UtcNow).TotalMinutes);
                        return Task.FromResult<(string, int)?>((tokenPair.AccessToken, remainingMinutes));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error reading JWT token for user {UserId}", userId);
                    }
                }
                return Task.FromResult<(string, int)?>(null);
            }
        }


        // Generates a secure random refresh token.
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        // Internal class to encapsulate token pairs.
        private class TokenPair
        {
            public string AccessToken { get; set; }
            public string RefreshToken { get; set; }
        }
    }
}


