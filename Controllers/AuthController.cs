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

        public AuthController(AuthService authService, JwtService jwtService)
        {
            _authService = authService;
            _jwtService = jwtService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Models.RegisterRequest request)
        {
            var result = await _authService.RegisterUserAsync(request);
            if (!result.Success)
                return BadRequest(result.Message);
            return Ok(result);
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] Models.LoginRequest request)
        {
            var authResult = _authService.LoginUserAsync(request).Result;
            if (!authResult.Success)
            {
                return Unauthorized(new { message = authResult.Message });
            }

            return Ok(new { success = authResult.Success, message = authResult.Message, accessToken = authResult.AccessToken, refreshToken = authResult.RefreshToken });
        }
        [HttpPost("refresh")]
        public IActionResult RefreshToken([FromBody] string refreshToken)
        {
            var newAccessToken = _jwtService.RefreshAccessToken(refreshToken);
            if (newAccessToken == null)
            {
                return Unauthorized(new { message = "Invalid or expired refresh token." });
            }
            return Ok(new { accessToken = newAccessToken });
        }
    }
}
