using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace POS.Models
{
    public class Product
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(100)]
        public string Name { get; set; }
        
        [MaxLength(500)]
        public string Description { get; set; }
        
        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal Price { get; set; }
        
        [Required]
        public int StockQuantity { get; set; }
        
        [MaxLength(20)]
        public string Unit { get; set; }
        
        public int ReorderThreshold { get; set; }
        
        public bool IsAvailable { get; set; } = true;
        
        public int CategoryId { get; set; }
        
        [ForeignKey("CategoryId")]
        public Category Category { get; set; }
        
        public DateTime CreatedAt { get; set; }
        
        public DateTime? UpdatedAt { get; set; }
        
        [MaxLength(255)]
        public string ImageUrl { get; set; }
        
        [MaxLength(255)]
        public string ImageDescription { get; set; }
    }
} 