namespace WebApplication1.Interface
{
    public interface ITokenRepository
    {
        Task StoreTokenAsync(string userId, string refreshToken);
        Task<string?> GetTokenAsync(string userId);
        Task RemoveTokenAsync(string userId);
        bool UserHasActiveSession(string userId);
        void StoreTokens(string userId, string accessToken, string refreshToken);
        void InvalidateTokens(string userId);
    }

}
