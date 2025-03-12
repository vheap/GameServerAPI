namespace WebApplication1.Models
{
    public class LoginRequest
    {
        public required string Identifier { get; set; } // Username or Email
        public required string Password { get; set; }
    }

}
