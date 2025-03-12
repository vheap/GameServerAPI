using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
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

