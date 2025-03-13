using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using WebApplication1.Models;
using WebApplication1.Services;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;
        private readonly JwtService _jwtService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(AuthService authService, JwtService jwtService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _jwtService = jwtService;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Models.RegisterRequest request)
        {
            var result = await _authService.RegisterUserAsync(request);
            if (!result.Success)
            {
                _logger.LogWarning("Registration failed for user {Username}: {Message}", request.Username, result.Message);
                return BadRequest(new { code = 400, message = result.Message });
            }

            _logger.LogInformation("User registered successfully: {Username}", request.Username);
            return Ok(new { code = 200, message = result.Message });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Models.LoginRequest request)
        {
            var authResult = await _authService.LoginUserAsync(request);
            if (!authResult.Success)
            {
                _logger.LogWarning("Login failed for identifier {Identifier}: {Message}", request.Identifier, authResult.Message);
                return Unauthorized(new { code = 401, message = authResult.Message });
            }

            _logger.LogInformation("Login successful for identifier: {Identifier}", request.Identifier);
            return Ok(new
            {
                code = 200,
                message = authResult.Message,
                accessToken = authResult.AccessToken,
                refreshToken = authResult.RefreshToken
            });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            var newTokens = await _jwtService.RefreshTokensAsync(request.RefreshToken);
            if (newTokens == null)
            {
                _logger.LogWarning("Token refresh failed for token: {RefreshToken}", request.RefreshToken);
                return Unauthorized(new { code = 401, message = "Invalid or expired refresh token." });
            }

            _logger.LogInformation("Token refreshed successfully.");
            return Ok(new
            {
                code = 200,
                message = "Token refreshed.",
                accessToken = newTokens.Value.AccessToken,
                refreshToken = newTokens.Value.RefreshToken
            });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
        {
            await _jwtService.LogoutAsync(request.UserId);
            _logger.LogInformation("User {UserId} logged out successfully.", request.UserId);
            return Ok(new { code = 200, message = "Logged out successfully." });
        }

        [HttpPost("debug-token")]
        public async Task<IActionResult> DebugToken([FromBody] DebugTokenRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Token) && string.IsNullOrWhiteSpace(request.UserId))
            {
                return BadRequest(new { code = 400, message = "Please provide either a token or a user id." });
            }

            // If a token is provided, verify against the in-memory store.
            if (!string.IsNullOrWhiteSpace(request.Token))
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                try
                {
                    var jwtToken = tokenHandler.ReadJwtToken(request.Token);
                    var userId = jwtToken.Subject;
                    if (string.IsNullOrWhiteSpace(userId))
                        return BadRequest(new { code = 400, message = "Invalid token: no user id found." });

                    // Check if the token is currently stored in memory to invalidate older ones. VIP!!
                    var tokenInfo = await _jwtService.GetTokenInfoByUserIdAsync(userId);
                    if (tokenInfo == null || tokenInfo.Value.AccessToken != request.Token)
                    {
                        return NotFound(new { code = 404, message = "Token is invalid or has been invalidated." });
                    }

                    int remainingMinutes = tokenInfo.Value.RemainingValidityMinutes;
                    return Ok(new
                    {
                        code = 200,
                        message = "Success",
                        userId = userId,
                        token = request.Token,
                        remainingValidityMinutes = remainingMinutes
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing token in debug-token endpoint.");
                    return BadRequest(new { code = 400, message = "Invalid token format." });
                }
            }
            // If a userId is provided, look up the token info.
            else if (!string.IsNullOrWhiteSpace(request.UserId))
            {
                var tokenInfo = await _jwtService.GetTokenInfoByUserIdAsync(request.UserId);
                if (tokenInfo == null)
                {
                    _logger.LogWarning("No token found for user id: {UserId}", request.UserId);
                    return NotFound(new { code = 404, message = "No token found for the provided user id." });
                }
                return Ok(new
                {
                    code = 200,
                    message = "Success",
                    userId = request.UserId,
                    token = tokenInfo.Value.AccessToken,
                    remainingValidityMinutes = tokenInfo.Value.RemainingValidityMinutes
                });
            }

            return BadRequest(new { code = 400, message = "Invalid request. Provide either token or userId." });
        }


        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            var result = await _authService.ChangePasswordAsync(request);
            if (!result.Success)
            {
                _logger.LogWarning("Change password failed for user {UserId}: {Message}", request.UserId, result.Message);
                return BadRequest(new { code = 400, message = result.Message });
            }
            _logger.LogInformation("Password changed successfully for user {UserId}", request.UserId);
            return Ok(new { code = 200, message = result.Message });
        }

        [HttpPost("change-alias")]
        public async Task<IActionResult> ChangeAlias([FromBody] ChangeAliasRequest request)
        {
            var result = await _authService.ChangeAliasAsync(request);
            if (!result.Success)
            {
                _logger.LogWarning("Change alias failed for user {UserId}: {Message}", request.UserId, result.Message);
                return BadRequest(new { code = 400, message = result.Message });
            }
            _logger.LogInformation("Alias changed successfully for user {UserId}", request.UserId);
            return Ok(new { code = 200, message = result.Message });
        }

        [HttpPost("change-email")]
        public async Task<IActionResult> ChangeEmail([FromBody] ChangeEmailRequest request)
        {
            var result = await _authService.ChangeEmailAsync(request);
            if (!result.Success)
            {
                _logger.LogWarning("Change email failed for user {UserId}: {Message}", request.UserId, result.Message);
                return BadRequest(new { code = 400, message = result.Message });
            }
            _logger.LogInformation("Email changed successfully for user {UserId}", request.UserId);
            return Ok(new { code = 200, message = result.Message });
        }
    }

        public class DebugTokenRequest
    {
        public string? Token { get; set; }
        public string? UserId { get; set; }
    }
    // DTO for refresh token requests
    public class RefreshRequest
    {
        public string RefreshToken { get; set; }
    }

    // DTO for logout requests
    public class LogoutRequest
    {
        public string UserId { get; set; }
    }
}

