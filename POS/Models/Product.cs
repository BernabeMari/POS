using System.ComponentModel.DataAnnotations;

namespace POS.Models
{
    public class Product
    {
        public int Id { get; set; }
        
        [Required]
        [StringLength(100)]
        public string Name { get; set; } = string.Empty;
        
        [StringLength(500)]
        public string Description { get; set; } = string.Empty;
        
        [Required]
        [Range(0.01, 10000)]
        public decimal Price { get; set; }
        
        public string ImageUrl { get; set; } = string.Empty;
        
        [StringLength(500)]
        public string ImageDescription { get; set; } = string.Empty;
        
        public bool IsAvailable { get; set; } = true;
        
        public int StockQuantity { get; set; } = 0;
        
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        
        public DateTime? UpdatedAt { get; set; }
    }
} 