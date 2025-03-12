using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Identity;
using WebApplication1.Models;
using WebApplication1.Repositories;
using WebApplication1.Utilities;
using Microsoft.Extensions.Caching.Memory;
using WebApplication1.Interface;

namespace WebApplication1.Services
{
    public class AuthService
    {
        private readonly UserRepository _userRepository;
        private readonly PasswordHasher _passwordHasher;
        private readonly JwtService _jwtService;
        private readonly ITokenRepository _tokenRepository;
        private readonly IMemoryCache _cache;

        public AuthService(UserRepository userRepository, PasswordHasher passwordHasher, JwtService jwtService, ITokenRepository tokenRepository)
        {
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _jwtService = jwtService;
            _tokenRepository = tokenRepository;
        }

        public async Task<AuthResult> RegisterUserAsync(Models.RegisterRequest request)
        {
            var (usernameExists, emailExists, aliasExists) = await _userRepository.CheckUserConflictsAsync(request.Username, request.Email, request.Alias);

            if (usernameExists)
                return new AuthResult(false, "Username is already taken.");
            if (emailExists)
                return new AuthResult(false, "Email is already in use.");
            if (aliasExists)
                return new AuthResult(false, "Alias is already taken.");

            var hashedPassword = _passwordHasher.HashPassword(request.Password);
            var user = new UserModel
            {
                Username = request.Username,
                Email = request.Email,
                PasswordHash = hashedPassword,
                Profile = new UserProfile { Alias = request.Alias }
            };

            await _userRepository.AddUserAsync(user);
            return new AuthResult(true, "User registered successfully.");
        }

        public async Task<AuthResult> LoginUserAsync(Models.LoginRequest request)
        {        
            var user = await _userRepository.GetUserByUsernameOrEmailAsync(request.Identifier);
            if (user == null)
                return new AuthResult(false, "Invalid credentials.");

            if (!_passwordHasher.VerifyPassword(request.Password, user.PasswordHash))
                return new AuthResult(false, "Invalid credentials.");

            var tokens = _jwtService.GenerateTokensAsync(user.UserID.ToString(), user.Username);
            if (tokens.Result.AccessToken == null)
                return new AuthResult(false, "Login failed. Bad AccessToken.");

            if (tokens.Result.RefreshToken == null)
                return new AuthResult(false, "Login failed. Bad RefreshToken.");

            return new AuthResult(true, "Login successful", tokens.Result.AccessToken, tokens.Result.RefreshToken);

        }


    }
}
