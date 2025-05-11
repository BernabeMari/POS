using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace POS.Models
{
    public enum TransactionType
    {
        TopUp,
        Payment,
        Refund
    }

    public class WalletTransaction
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        public string UserId { get; set; }
        
        [ForeignKey("UserId")]
        public ApplicationUser User { get; set; }
        
        [Required]
        public DateTime Timestamp { get; set; } = DateTime.Now;
        
        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal Amount { get; set; }
        
        [Required]
        public TransactionType Type { get; set; }
        
        [MaxLength(50)]
        public string ReferenceNumber { get; set; } = string.Empty;
        
        [MaxLength(255)]
        public string Description { get; set; } = string.Empty;
        
        // If this transaction is for an order
        public int? OrderId { get; set; }
        
        [ForeignKey("OrderId")]
        public Order Order { get; set; }
        
        // Previous and new balance for audit trail
        [Column(TypeName = "decimal(18,2)")]
        public decimal PreviousBalance { get; set; }
        
        [Column(TypeName = "decimal(18,2)")]
        public decimal NewBalance { get; set; }

        // Navigation properties
        public Wallet Wallet { get; set; }
    }
} 