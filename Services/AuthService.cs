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

        public async Task<AuthResult> ChangePasswordAsync(ChangePasswordRequest request)
        {
            var user = await _userRepository.GetUserByIdAsync(request.UserId);
            if (user == null)
                return new AuthResult(false, "User not found.");

            if (!_passwordHasher.VerifyPassword(request.CurrentPassword, user.PasswordHash))
                return new AuthResult(false, "Current password is incorrect.");

            user.PasswordHash = _passwordHasher.HashPassword(request.NewPassword);
            await _userRepository.UpdateUserAsync(user);

            // Invalidate existing tokens immediately. Very important, never leave behind inactive tokens.
            await _jwtService.LogoutAsync(user.UserID.ToString());

            return new AuthResult(true, "Password updated successfully. All active sessions have been invalidated.");
        }

        public async Task<AuthResult> ChangeAliasAsync(ChangeAliasRequest request)
        {
            var user = await _userRepository.GetUserByIdAsync(request.UserId);
            if (user == null)
                return new AuthResult(false, "User not found.");

            // Validate alias using our rules
            var (isValid, validationMessage) = ValidationRules.CheckAliasValidity(request.NewAlias);
            if (!isValid)
                return new AuthResult(false, validationMessage);

            // Check if the alias already exists on a different user
            bool aliasConflict = await _userRepository.CheckAliasConflictAsync(request.UserId, request.NewAlias);
            if (aliasConflict)
                return new AuthResult(false, "Alias is already taken by another user.");

            user.Profile.Alias = request.NewAlias;
            await _userRepository.UpdateUserAsync(user);
            return new AuthResult(true, "Alias updated successfully.");
        }

        public async Task<AuthResult> ChangeEmailAsync(ChangeEmailRequest request)
        {
            var user = await _userRepository.GetUserByIdAsync(request.UserId);
            if (user == null)
                return new AuthResult(false, "User not found.");

            // Validate email format
            var (isValid, validationMessage) = ValidationRules.CheckEmailValidity(request.NewEmail);
            if (!isValid)
                return new AuthResult(false, validationMessage);

            // Check if the email is already used by another account
            bool emailConflict = await _userRepository.CheckEmailConflictAsync(request.UserId, request.NewEmail);
            if (emailConflict)
                return new AuthResult(false, "Email is already in use by another account.");

            user.Email = request.NewEmail;
            await _userRepository.UpdateUserAsync(user);
            return new AuthResult(true, "Email updated successfully.");
        }

    }
}
