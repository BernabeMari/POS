using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using POS.Services;

namespace POS.Models
{
    public class ProductIngredient
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        public int PageElementId { get; set; }
        
        [ForeignKey("PageElementId")]
        public PageElement PageElement { get; set; }
        
        private string _ingredientName = string.Empty;
        
        [Required]
        [MaxLength(100)]
        public string IngredientName 
        { 
            get => _ingredientName;
            set => _ingredientName = SqlInputSanitizer.SanitizeString(value ?? string.Empty);
        }
        
        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal Quantity { get; set; }
        
        private string _unit = "g";
        
        [Required]
        [MaxLength(20)]
        public string Unit 
        { 
            get => _unit;
            set => _unit = SqlInputSanitizer.SanitizeString(value ?? "g");
        }
        
        private string _notes = string.Empty;
        
        [MaxLength(255)]
        public string Notes 
        { 
            get => _notes;
            set => _notes = SqlInputSanitizer.SanitizeString(value ?? string.Empty);
        }
    }
} 