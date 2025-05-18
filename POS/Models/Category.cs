using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;

namespace POS.Models
{
    public class Category
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        [MaxLength(50)]
        public string Name { get; set; }
        
        [MaxLength(200)]
        public string Description { get; set; }
        
        // Navigation property for products in this category
        public ICollection<Product> Products { get; set; }
    }
} 