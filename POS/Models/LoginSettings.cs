using System.ComponentModel.DataAnnotations;

namespace POS.Models
{
    public class LoginSettings
    {
        public int Id { get; set; }
        
        [Range(1, 10, ErrorMessage = "Maximum attempts must be between 1 and 10")]
        [Display(Name = "Maximum Login Attempts")]
        public int MaxLoginAttempts { get; set; } = 3;
        
        [Range(10, 3600, ErrorMessage = "Lockout duration must be between 10 seconds and 1 hour")]
        [Display(Name = "Lockout Duration (seconds)")]
        public int LockoutDuration { get; set; } = 60;
        
        [Display(Name = "Enable Account Lockout")]
        public bool EnableLockout { get; set; } = true;
        
        [Display(Name = "Last Updated")]
        public DateTime LastUpdated { get; set; } = DateTime.Now;
        
        [Display(Name = "Updated By")]
        public string UpdatedBy { get; set; } = "System";
    }
} 