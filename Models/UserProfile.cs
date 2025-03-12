using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class UserProfile
    {
        [Key]
        public int UserID { get; set; }
        public string Alias { get; set; }
        public int Level { get; set; } = 1;
        public UserModel User { get; set; }
    }
}
