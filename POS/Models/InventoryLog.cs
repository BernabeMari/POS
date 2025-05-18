using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace POS.Models
{
    public class InventoryLog
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        public int ProductId { get; set; }
        
        [ForeignKey("ProductId")]
        public Product Product { get; set; }
        
        [Required]
        public int PreviousQuantity { get; set; }
        
        [Required]
        public int NewQuantity { get; set; }
        
        [Required]
        [MaxLength(50)]
        public string ChangeReason { get; set; }
        
        [MaxLength(500)]
        public string Notes { get; set; }
        
        [Required]
        public string UserId { get; set; }
        
        [ForeignKey("UserId")]
        public ApplicationUser User { get; set; }
        
        [Required]
        public DateTime Timestamp { get; set; }
    }
} 