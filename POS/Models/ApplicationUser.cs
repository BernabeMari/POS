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
        
        // Senior Citizen and PWD status
        public bool IsSeniorCitizen { get; set; } = false;
        public bool IsPWD { get; set; } = false;
        
        // Sandbox payment system properties
        public decimal WalletBalance { get; set; } = 1000.00m; // Default starting balance of 1000
        public DateTime LastWalletTopUp { get; set; } = DateTime.Now;
    }
} 