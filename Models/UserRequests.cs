namespace WebApplication1.Models
{
    public class UserRequests
    {
    }
    public class ChangePasswordRequest
    {
        public string UserId { get; set; }
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class ChangeAliasRequest
    {
        public string UserId { get; set; }
        public string NewAlias { get; set; }
    }

    public class ChangeEmailRequest
    {
        public string UserId { get; set; }
        public string NewEmail { get; set; }
    }
}
