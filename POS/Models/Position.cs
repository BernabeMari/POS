using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace POS.Models
{
    [Table("AspUserPositions")]
    public class Position
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [StringLength(50)]
        public string Name { get; set; } = string.Empty;
        
        [StringLength(255)]
        public string Description { get; set; } = string.Empty;
        
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        
        public bool IsActive { get; set; } = true;
    }
} 