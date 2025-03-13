using System.Net.Mail;
using System.Text.RegularExpressions;

namespace WebApplication1.Utilities
{
    public static class ValidationRules
    {
        /// <summary>
        /// Checks if the alias is valid. Returns (true, message) if valid; otherwise (false, error message).
        /// Rules: not empty, maximum 20 characters, only alphanumeric characters (no spaces or special characters).
        /// </summary>
        public static (bool IsValid, string Message) CheckAliasValidity(string alias)
        {
            if (string.IsNullOrWhiteSpace(alias))
                return (false, "Alias cannot be empty.");

            if (alias.Length > 20)
                return (false, "Alias cannot be longer than 20 characters.");

            // Allow only letters and numbers.
            if (!Regex.IsMatch(alias, "^[A-Za-z0-9]+$"))
                return (false, "Alias can only contain alphanumeric characters (no spaces or special characters).");

            return (true, "Alias is valid.");
        }

        /// <summary>
        /// Checks if the email is in a proper format.
        /// </summary>
        public static (bool IsValid, string Message) CheckEmailValidity(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return (false, "Email cannot be empty.");

            try
            {
                var addr = new MailAddress(email);
                if (addr.Address != email)
                    return (false, "Email format is invalid.");
            }
            catch
            {
                return (false, "Email format is invalid.");
            }

            return (true, "Email is valid.");
        }
    }
}
