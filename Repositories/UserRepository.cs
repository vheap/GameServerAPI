using Microsoft.EntityFrameworkCore;
using WebApplication1.Models;

namespace WebApplication1.Repositories
{
    public class UserRepository
    {
        private readonly AppDbContext _context;

        public UserRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task AddUserAsync(UserModel user)
        {
            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();
        }
        
        public async Task<(bool UsernameExists, bool EmailExists, bool AliasExists)> CheckUserConflictsAsync(string username, string email, string alias)
        {
            var user = await _context.Users
                .Where(u => u.Username == username || u.Email == email)
                .Select(u => new { u.Username, u.Email })
                .FirstOrDefaultAsync();

            var aliasExists = await _context.UserProfiles.AnyAsync(p => p.Alias == alias);

            return (user?.Username == username, user?.Email == email, aliasExists);
        }

        public async Task<UserModel?> GetUserByUsernameOrEmailAsync(string identifier)
        {
            return await _context.Users.FirstOrDefaultAsync(u => u.Username == identifier || u.Email == identifier);
        }

    }
}
