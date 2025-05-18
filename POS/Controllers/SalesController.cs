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
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin,Manager,Employee")]
    public class SalesController : ControllerBase
    {
        private readonly IOrderService _orderService;
        private readonly ILogger<SalesController> _logger;
        private readonly ApplicationDbContext _context;

        public SalesController(
            IOrderService orderService, 
            ILogger<SalesController> logger,
            ApplicationDbContext context)
        {
            _orderService = orderService;
            _logger = logger;
            _context = context;
        }

        [HttpGet("performance")]
        public async Task<IActionResult> Performance()
        {
            // Check if the user is authenticated before proceeding
            if (!User.Identity.IsAuthenticated)
            {
                _logger.LogWarning("Unauthorized access attempt to performance data");
                return Unauthorized(new { error = "Unauthorized access" });
            }

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isAdmin = User.IsInRole("Admin");
            var isManager = User.IsInRole("Manager");
            var isAssistantManagerWithAccess = false;
            
            // Check if the user is an Assistant Manager with Manager access
            if (User.IsInRole("Employee") && !isAdmin && !isManager)
            {
                var user = await _context.Users
                    .Include(u => u.Position)
                    .FirstOrDefaultAsync(u => u.Id == userId);
                    
                if (user?.Position?.Name == "Assistant Manager")
                {
                    isAssistantManagerWithAccess = await _context.UserPreferences
                        .AnyAsync(p => p.UserId == userId && p.Key == "ManagerAccess" && p.Value == "true");
                }
            }

            // Check if the user has the required role or special access
            if (!isManager && !isAdmin && !isAssistantManagerWithAccess)
            {
                _logger.LogWarning($"Access denied for user {User.Identity.Name} - insufficient permissions");
                return Forbid();
            }
            
            try
            {
                _logger.LogInformation("Fetching store performance data for Manager dashboard");
                
                // Get orders awaiting discount approval
                var discountOrders = await _orderService.GetOrdersAwaitingDiscountApprovalAsync();
                _logger.LogInformation($"Found {discountOrders.Count()} orders awaiting discount approval");
                
                // Format the orders for the dashboard display
                var formattedDiscountOrders = discountOrders.Select(order => new {
                    id = order.Id,
                    customerName = order.User?.FullName ?? "Anonymous",
                    itemCount = 1, // Consider using order items when available
                    total = $"${order.TotalPrice:F2}",
                    originalTotal = $"${order.OriginalTotalPrice:F2}",
                    timeAgo = GetTimeAgo(order.CreatedAt),
                    status = order.Status.ToString(),
                    discountType = order.DiscountType ?? "Unknown",
                    discountRequested = order.IsDiscountRequested
                }).ToList();
                
                // Sample store performance data (in a real app, this would come from a service)
                var result = new {
                    todaySales = "$2,850.75",
                    salesTarget = "$3,500.00",
                    percentOfDailyGoal = 81,
                    customerCount = 187,
                    avgOrderValue = "$15.24",
                    discountRequests = formattedDiscountOrders
                };

                _logger.LogInformation("Successfully generated store performance data response");
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching store performance data");
                return StatusCode(500, new { error = "Failed to fetch store performance data" });
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