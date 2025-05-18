using System;
using System.ComponentModel.DataAnnotations;

namespace POS.Models
{
    public class EncryptionSettings
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [StringLength(50)]
        public string SettingName { get; set; }
        
        [Required]
        [StringLength(100)]
        public string SettingValue { get; set; }
        
        [StringLength(255)]
        public string Description { get; set; }
        
        [Required]
        public DateTime LastModified { get; set; } = DateTime.UtcNow;
        
        [StringLength(100)]
        public string ModifiedBy { get; set; }
    }
} 