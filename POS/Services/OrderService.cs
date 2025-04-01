using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using POS.Data;
using POS.Models;

namespace POS.Services
{
    public class OrderService : IOrderService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<OrderService> _logger;

        public OrderService(ApplicationDbContext context, ILogger<OrderService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<Order>> GetAllOrdersAsync()
        {
            return await _context.Orders
                .Include(o => o.User)
                .Include(o => o.AssignedEmployee)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<Order>> GetOrdersByUserIdAsync(string userId)
        {
            return await _context.Orders
                .Include(o => o.AssignedEmployee)
                .Where(o => o.UserId == userId)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<Order>> GetOrdersByEmployeeIdAsync(string employeeId)
        {
            return await _context.Orders
                .Include(o => o.User)
                .Where(o => o.AssignedToEmployeeId == employeeId)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<Order>> GetPendingOrdersAsync()
        {
            return await _context.Orders
                .Include(o => o.User)
                .Where(o => o.Status == OrderStatus.Pending)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }

        public async Task<Order> GetOrderByIdAsync(int id)
        {
            return await _context.Orders
                .Include(o => o.User)
                .Include(o => o.AssignedEmployee)
                .FirstOrDefaultAsync(o => o.Id == id);
        }

        public async Task<Order> CreateOrderAsync(Order order)
        {
            // Calculate total price if not set
            if (order.TotalPrice == 0)
            {
                order.TotalPrice = order.Price * order.Quantity;
            }
            
            order.CreatedAt = DateTime.Now;
            _context.Orders.Add(order);
            await _context.SaveChangesAsync();
            return order;
        }

        public async Task<Order> UpdateOrderAsync(Order order)
        {
            order.UpdatedAt = DateTime.Now;
            _context.Entry(order).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return order;
        }

        public async Task<bool> DeleteOrderAsync(int id)
        {
            var order = await _context.Orders.FindAsync(id);
            if (order == null)
                return false;

            _context.Orders.Remove(order);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<Order> AssignOrderToEmployeeAsync(int orderId, string employeeId)
        {
            var order = await _context.Orders.FindAsync(orderId);
            if (order == null)
                return null;
                
            order.AssignedToEmployeeId = employeeId;
            order.Status = OrderStatus.OrderReceived;
            order.UpdatedAt = DateTime.Now;
            
            await _context.SaveChangesAsync();
            return order;
        }

        public async Task<Order> UpdateOrderStatusAsync(int orderId, OrderStatus status)
        {
            var order = await _context.Orders.FindAsync(orderId);
            if (order == null)
                return null;

            order.Status = status;
            order.UpdatedAt = DateTime.Now;
            
            await _context.SaveChangesAsync();
            return order;
        }
        
        public async Task<IEnumerable<Order>> GetNewOrdersAsync()
        {
            _logger.LogInformation("Fetching new orders...");
            
            try
            {
                // Get all pending orders that aren't assigned to anyone
                var orders = await _context.Orders
                    .Include(o => o.User)
                    .Where(o => o.Status == OrderStatus.Pending && o.AssignedToEmployeeId == null)
                    .OrderByDescending(o => o.CreatedAt)
                    .ToListAsync();
                
                _logger.LogInformation($"Found {orders.Count} new orders");
                
                return orders;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching new orders");
                return Enumerable.Empty<Order>();
            }
        }
        
        public async Task<IEnumerable<Order>> GetAssignedOrdersAsync(string employeeId)
        {
            return await _context.Orders
                .Include(o => o.User)
                .Where(o => o.AssignedToEmployeeId == employeeId && 
                          (o.Status == OrderStatus.Processing || 
                           o.Status == OrderStatus.OrderReceived || 
                           o.Status == OrderStatus.OnGoing))
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }
        
        public async Task<IEnumerable<Order>> GetOrderHistoryAsync(string employeeId = null)
        {
            var query = _context.Orders
                .Include(o => o.User)
                .Include(o => o.AssignedEmployee)
                .Where(o => o.Status == OrderStatus.Completed || 
                          o.Status == OrderStatus.Complete || 
                          o.Status == OrderStatus.Cancelled);
                
            if (!string.IsNullOrEmpty(employeeId))
            {
                query = query.Where(o => o.AssignedToEmployeeId == employeeId);
            }
            
            return await query
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }
        
        public async Task<Order> CompleteOrderAsync(int orderId)
        {
            var order = await _context.Orders.FindAsync(orderId);
            if (order == null)
                return null;
            
            order.Status = OrderStatus.Completed;
            order.UpdatedAt = DateTime.Now;
            
            await _context.SaveChangesAsync();
            return order;
        }

        public async Task<IEnumerable<Order>> GetLatestOrdersAsync(int sinceId = 0)
        {
            return await _context.Orders
                .Include(o => o.User)
                .Where(o => o.Id > sinceId && o.Status == OrderStatus.Pending)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }
    }
} 