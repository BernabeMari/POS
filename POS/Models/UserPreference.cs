using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace POS.Models
{
    public class UserPreference
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        public string UserId { get; set; }
        
        [Required]
        [MaxLength(100)]
        public string Key { get; set; }
        
        [Required]
        public string Value { get; set; }
        
        [ForeignKey("UserId")]
        public virtual ApplicationUser User { get; set; }
    }
} 