using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Identity;
using WebApplication1.Models;
using WebApplication1.Repositories;
using WebApplication1.Utilities;

namespace WebApplication1.Services
{
    public class AuthService
    {
        private readonly UserRepository _userRepository;
        private readonly PasswordHasher _passwordHasher;
        private readonly JwtService _jwtService;

        public AuthService(UserRepository userRepository, PasswordHasher passwordHasher, JwtService jwtService)
        {
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _jwtService = jwtService;
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
                return new AuthResult(false, "Invalid username or email.");

            if (!_passwordHasher.VerifyPassword(request.Password, user.PasswordHash))
                return new AuthResult(false, "Incorrect password.");

            var tokens = _jwtService.GenerateTokens(user.UserID.ToString(), user.Username);
            if(tokens.AccessToken == null)
                return new AuthResult(false, "Login failed. Bad AccessToken.");

            if (tokens.RefreshToken == null)
                return new AuthResult(false, "Login failed. Bad RefreshToken.");

            return new AuthResult(true, "Login successful", tokens.AccessToken, tokens.RefreshToken);

            var token = _jwtService.GenerateTokens(user.UserID.ToString(), user.Username).RefreshToken;
            Console.WriteLine($"Debug: {token}");
            return new AuthResult(true, "Login successful.", token);


        }

    }
}
