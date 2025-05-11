using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace POS.Models
{
    public class Wallet
    {
        [Key]
        public int Id { get; set; }
        
        [Required]
        public string UserId { get; set; }
        
        [Required]
        [Column(TypeName = "decimal(18,2)")]
        public decimal Balance { get; set; }
        
        [Required]
        public DateTime CreatedAt { get; set; }
        
        public DateTime? UpdatedAt { get; set; }

        // Navigation properties
        public ApplicationUser User { get; set; }
        public ICollection<WalletTransaction> Transactions { get; set; }
    }
} 