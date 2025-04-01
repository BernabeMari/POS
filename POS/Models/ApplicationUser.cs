using Microsoft.AspNetCore.Identity;

namespace POS.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; } = string.Empty;
        public bool IsAdmin { get; set; } = false;
        public bool IsEmployee { get; set; } = false;
        public int? PositionId { get; set; }
        public virtual Position? Position { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }
} 