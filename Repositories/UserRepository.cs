using Microsoft.EntityFrameworkCore;
using WebApplication1.Models;

namespace WebApplication1.Repositories
{
    public class UserRepository
    {
        private readonly AppDbContext _context;
        private readonly ILogger<UserRepository> _logger;
        public UserRepository(AppDbContext context, ILogger<UserRepository> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<bool> AddUserAsync(UserModel user)
        {
            //await _context.Users.AddAsync(user);
            //await _context.SaveChangesAsync();
            try
            {
                await _context.Users.AddAsync(user);
                await _context.SaveChangesAsync();
                _logger.LogInformation("User added successfully: {Username}", user.Username);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while adding user: {Username}", user.Username);
                throw;
            }
        }
        //Check for any conflict cause why not lmao.
        public async Task<(bool UsernameExists, bool EmailExists, bool AliasExists)> CheckUserConflictsAsync(string username, string email, string alias)
        {
            try
            {
                var usernameTask = _context.Users.AnyAsync(u => u.Username == username);
                var emailTask = _context.Users.AnyAsync(u => u.Email == email);
                var aliasTask = _context.UserProfiles.AnyAsync(p => p.Alias == alias);

                await Task.WhenAll(usernameTask, emailTask, aliasTask);

                bool usernameExists = usernameTask.Result;
                bool emailExists = emailTask.Result;
                bool aliasExists = aliasTask.Result;

                _logger.LogInformation("Conflict check for Username: {Username}, Email: {Email}, Alias: {Alias} - " +
                                       "Conflicts found: UsernameExists={UsernameExists}, EmailExists={EmailExists}, AliasExists={AliasExists}",
                                       username, email, alias, usernameExists, emailExists, aliasExists);

                return (usernameExists, emailExists, aliasExists);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during conflict check for Username: {Username}, Email: {Email}, Alias: {Alias}",
                                 username, email, alias);
                throw;
            }
        }
        //Get User by an identifier. Different from their unique ID.
        public async Task<UserModel?> GetUserByUsernameOrEmailAsync(string identifier)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == identifier || u.Email == identifier);
                if (user != null)
                {
                    _logger.LogInformation("User found for identifier: {Identifier}", identifier);
                }
                else
                {
                    _logger.LogWarning("No user found for identifier: {Identifier}", identifier);
                }
                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while retrieving user for identifier: {Identifier}", identifier);
                throw;
            }
        }

        //Get user by Id
        public async Task<UserModel?> GetUserByIdAsync(string userId)
        {
            try
            {
                // Assuming userId is stored as a string or can be compared via ToString().
                var user = await _context.Users.FirstOrDefaultAsync(u => u.UserID.ToString() == userId);
                if (user != null)
                {
                    _logger.LogInformation("User found for userId: {UserId}", userId);
                }
                else
                {
                    _logger.LogWarning("No user found for userId: {UserId}", userId);
                }
                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while retrieving user for userId: {UserId}", userId);
                throw;
            }
        }

        //Update an existing user model.
        public async Task UpdateUserAsync(UserModel user)
        {
            try
            {
                _context.Users.Update(user);
                await _context.SaveChangesAsync();
                _logger.LogInformation("User updated successfully: {UserId}", user.UserID);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while updating user: {UserId}", user.UserID);
                throw;
            }
        }

        //Check if alias already exists for another user.
        public async Task<bool> CheckAliasConflictAsync(string userId, string newAlias)
        {
            try
            {
                bool exists = await _context.UserProfiles.AnyAsync(
                    p => p.Alias == newAlias && p.UserID.ToString() != userId);
                _logger.LogInformation("Alias conflict check for userId {UserId} with alias {Alias}: {Exists}",
                    userId, newAlias, exists);
                return exists;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while checking alias conflict for userId: {UserId}", userId);
                throw;
            }
        }

        //Check if email already exists for another user.
        public async Task<bool> CheckEmailConflictAsync(string userId, string newEmail)
        {
            try
            {
                bool exists = await _context.Users.AnyAsync(
                    u => u.Email == newEmail && u.UserID.ToString() != userId);
                _logger.LogInformation("Email conflict check for userId {UserId} with email {Email}: {Exists}",
                    userId, newEmail, exists);
                return exists;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while checking email conflict for userId: {UserId}", userId);
                throw;
            }
        }
       

    }
}
