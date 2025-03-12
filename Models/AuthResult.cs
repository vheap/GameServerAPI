namespace WebApplication1.Models
{
    public class AuthResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }


        public AuthResult(bool success, string message, string? accessToken = null, string? refreshToken = null)
        {
            Success = success;
            Message = message;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
        }
    }
}
