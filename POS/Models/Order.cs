using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace POS.Models
{
    public class Order
    {
        public int Id { get; set; }
        
        [Required]
        public string UserId { get; set; } = string.Empty;
        
        [ForeignKey("UserId")]
        public virtual ApplicationUser User { get; set; }
        
        public string? AssignedToEmployeeId { get; set; }
        
        [ForeignKey("AssignedToEmployeeId")]
        public virtual ApplicationUser AssignedEmployee { get; set; }
        
        [Required]
        public string ProductName { get; set; } = string.Empty;
        
        [Required]
        public string ProductImageUrl { get; set; } = string.Empty;
        
        [StringLength(500)]
        public string ProductImageDescription { get; set; } = string.Empty;
        
        [Required]
        public decimal Price { get; set; }
        
        [Required]
        public int Quantity { get; set; } = 1;
        
        [Required]
        public decimal TotalPrice { get; set; }
        
        [StringLength(500)]
        public string Notes { get; set; } = string.Empty;
        
        [Required]
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        
        public DateTime? UpdatedAt { get; set; }
        
        [Required]
        public OrderStatus Status { get; set; } = OrderStatus.Pending;
    }
    
    public enum OrderStatus
    {
        Pending,
        OrderReceived,
        OnGoing,
        ReadyToServe,
        Processing,
        Completed,
        Complete = Completed,
        Cancelled
    }
} 