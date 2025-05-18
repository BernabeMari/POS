using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace POS.Models
{
    public class Stock
    {
        [Key]
        public int StockID { get; set; }
        
        [Required]
        [StringLength(100)]
        public string ProductName { get; set; }
        
        [Required]
        [StringLength(50)]
        public string Category { get; set; }
        
        [Required]
        [Column(TypeName = "decimal(10, 2)")]
        public decimal Quantity { get; set; }
        
        [Required]
        [StringLength(20)]
        public string UnitType { get; set; }
        
        [Required]
        [Column(TypeName = "decimal(10, 2)")]
        public decimal ThresholdLevel { get; set; }
        
        public DateTime LastUpdated { get; set; } = DateTime.Now;
        
        public string? UpdatedBy { get; set; }
        
        public string? Notes { get; set; }
    }
    
    public class StockHistory
    {
        [Key]
        public int HistoryID { get; set; }
        
        [Required]
        public int StockID { get; set; }
        
        [ForeignKey("StockID")]
        public Stock Stock { get; set; }
        
        [Column(TypeName = "decimal(10, 2)")]
        public decimal PreviousQuantity { get; set; }
        
        [Column(TypeName = "decimal(10, 2)")]
        public decimal NewQuantity { get; set; }
        
        [Required]
        [StringLength(50)]
        public string ChangeReason { get; set; }
        
        public string? ChangedBy { get; set; }
        
        public DateTime ChangeDate { get; set; } = DateTime.Now;
        
        public string? Notes { get; set; }
    }
} 