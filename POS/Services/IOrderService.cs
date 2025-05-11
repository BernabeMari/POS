using POS.Models;

namespace POS.Services
{
    public interface IOrderService
    {
        Task<IEnumerable<Order>> GetAllOrdersAsync();
        Task<IEnumerable<Order>> GetOrdersByUserIdAsync(string userId);
        Task<IEnumerable<Order>> GetOrdersByEmployeeIdAsync(string employeeId);
        Task<IEnumerable<Order>> GetPendingOrdersAsync();
        Task<Order> GetOrderByIdAsync(int id);
        Task<Order> CreateOrderAsync(Order order);
        Task<Order> CreateOrderAndUpdateStockAsync(Order order, PageElement productElement);
        Task<Order> UpdateOrderAsync(Order order);
        Task<bool> DeleteOrderAsync(int id);
        Task<Order> AssignOrderToEmployeeAsync(int orderId, string employeeId);
        Task<Order> UpdateOrderStatusAsync(int orderId, OrderStatus status);
        
        // New methods for employee dashboard
        Task<IEnumerable<Order>> GetNewOrdersAsync();
        Task<IEnumerable<Order>> GetAssignedOrdersAsync(string employeeId);
        Task<IEnumerable<Order>> GetOrderHistoryAsync(string employeeId = null);
        Task<Order> CompleteOrderAsync(int orderId);
        
        // Method for real-time order notifications
        Task<IEnumerable<Order>> GetLatestOrdersAsync(int sinceId = 0);
        
        // Methods for discount management
        Task<Order> RequestDiscountAsync(int orderId, string discountType);
        Task<Order> ApproveDiscountAsync(int orderId, string managerId, decimal discountPercentage = 20);
        Task<Order> DenyDiscountAsync(int orderId, string managerId);
        Task<Order> SkipDiscountAsync(int orderId);
        Task<IEnumerable<Order>> GetOrdersAwaitingDiscountApprovalAsync();
    }
} 