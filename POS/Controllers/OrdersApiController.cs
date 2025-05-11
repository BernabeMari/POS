using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using POS.Data;

namespace POS.Controllers
{
    [Route("api/orders")]
    [ApiController]
    [Authorize(Roles = "Admin,Manager,Employee")]
    public class OrdersApiController : ControllerBase
    {
        private readonly IOrderService _orderService;
        private readonly ILogger<OrdersApiController> _logger;
        private readonly ApplicationDbContext _context;

        public OrdersApiController(
            IOrderService orderService, 
            ILogger<OrdersApiController> logger,
            ApplicationDbContext context)
        {
            _orderService = orderService;
            _logger = logger;
            _context = context;
        }

        [HttpGet("recent")]
        public async Task<IActionResult> Recent()
        {
            // Check if the user is authenticated before proceeding
            if (!User.Identity.IsAuthenticated)
            {
                _logger.LogWarning("Unauthorized access attempt to recent orders");
                return Unauthorized(new { error = "Unauthorized access" });
            }

            // Check if the user has the required role
            if (!User.IsInRole("Employee") && !User.IsInRole("Admin") && !User.IsInRole("Manager"))
            {
                _logger.LogWarning($"Access denied for user {User.Identity.Name} - insufficient permissions");
                return Forbid();
            }
            
            try
            {
                _logger.LogInformation("Fetching recent orders for dashboard");
                
                // Get all orders (we'll format them for display)
                var orders = await _orderService.GetAllOrdersAsync();
                
                // Format the orders for the dashboard display
                var formattedOrders = orders.Take(10).Select(order => new {
                    id = order.Id,
                    customerName = order.User?.FullName ?? "Anonymous",
                    itemCount = 1, // Consider using order items when available
                    total = $"${order.TotalPrice:F2}",
                    timeAgo = GetTimeAgo(order.CreatedAt),
                    status = order.Status.ToString()
                }).ToList();
                
                return Ok(formattedOrders);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching recent orders");
                return StatusCode(500, new { error = "Failed to fetch recent orders" });
            }
        }
        
        [HttpGet("{id}")]
        [Authorize(Roles = "Admin,Manager,Employee")]
        public async Task<IActionResult> GetById(int id)
        {
            // Check if the user is authenticated before proceeding
            if (!User.Identity.IsAuthenticated)
            {
                _logger.LogWarning($"Unauthorized access attempt to order details for ID: {id}");
                return Unauthorized(new { error = "Unauthorized access" });
            }

            // Check if the user has appropriate role or Manager position
            bool isAuthorized = User.IsInRole("Admin") || User.IsInRole("Manager");
            
            if (!isAuthorized && User.IsInRole("Employee"))
            {
                // Check if this employee has Manager position or is an Assistant Manager with Manager access
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var user = await _context.Users
                    .Include(u => u.Position)
                    .FirstOrDefaultAsync(u => u.Id == userId);
                    
                if (user?.Position?.Name == "Manager")
                {
                    isAuthorized = true;
                }
                else if (user?.Position?.Name == "Assistant Manager")
                {
                    // Check if this Assistant Manager has been granted Manager dashboard access
                    isAuthorized = await _context.UserPreferences
                        .AnyAsync(p => p.UserId == userId && p.Key == "ManagerAccess" && p.Value == "true");
                }
            }
            
            if (!isAuthorized)
            {
                _logger.LogWarning($"Access denied for user {User.Identity.Name} - insufficient permissions");
                return Forbid();
            }
            
            try
            {
                _logger.LogInformation($"Fetching order details for order ID: {id}");
                
                // Get the order by ID
                var order = await _orderService.GetOrderByIdAsync(id);
                
                if (order == null)
                {
                    return NotFound(new { error = "Order not found" });
                }
                
                // Format the order for display
                var formattedOrder = new {
                    id = order.Id,
                    customerName = order.User?.FullName ?? "Anonymous",
                    itemCount = 1, // Consider using order items when available
                    total = $"${order.TotalPrice:F2}",
                    originalTotal = $"${order.OriginalTotalPrice:F2}",
                    timeAgo = GetTimeAgo(order.CreatedAt),
                    status = order.Status.ToString(),
                    discountType = order.DiscountType ?? "None",
                    discountRequested = order.IsDiscountRequested,
                    discountApproved = order.IsDiscountApproved,
                    discountPercentage = order.DiscountPercentage,
                    discountAmount = $"${order.DiscountAmount:F2}",
                    notes = order.Notes
                };
                
                return Ok(formattedOrder);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error fetching order details for order ID: {id}");
                return StatusCode(500, new { error = "Failed to fetch order details" });
            }
        }
        
        private string GetTimeAgo(DateTime dateTime)
        {
            var span = DateTime.Now - dateTime;
            
            if (span.Days > 0)
                return $"{span.Days} day{(span.Days > 1 ? "s" : "")} ago";
            
            if (span.Hours > 0)
                return $"{span.Hours} hour{(span.Hours > 1 ? "s" : "")} ago";
                
            if (span.Minutes > 0)
                return $"{span.Minutes} min{(span.Minutes > 1 ? "s" : "")} ago";
                
            return "Just now";
        }
    }
} 