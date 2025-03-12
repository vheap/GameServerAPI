using Microsoft.Extensions.Caching.Memory;
using System.Collections.Concurrent;
using WebApplication1.Interface;

namespace WebApplication1.Repositories
{
    public class TokenRepository : ITokenRepository
    {
        private readonly IMemoryCache _cache;

        public TokenRepository(IMemoryCache cache)
        {
            _cache = cache;
        }

        public async Task StoreTokenAsync(string userId, string refreshToken)
        {
            _cache.Set(userId, refreshToken, TimeSpan.FromDays(7));
            await Task.CompletedTask;
        }

        public async Task<string?> GetTokenAsync(string userId)
        {
            _cache.TryGetValue(userId, out string? token);
            return await Task.FromResult(token);
        }

        public async Task RemoveTokenAsync(string userId)
        {
            _cache.Remove(userId);
            await Task.CompletedTask;
        }
        private readonly ConcurrentDictionary<string, (string AccessToken, string RefreshToken)> _activeSessions = new();

        public bool UserHasActiveSession(string userId)
        {
            return _activeSessions.ContainsKey(userId);
        }

        public void StoreTokens(string userId, string accessToken, string refreshToken)
        {
            _activeSessions[userId] = (accessToken, refreshToken);
        }

        public void InvalidateTokens(string userId)
        {
            _activeSessions.TryRemove(userId, out _);
        }
    }

}
