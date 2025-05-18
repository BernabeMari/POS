using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using POS.Data;

namespace POS.Pages.api.sales
{
    [Authorize(Roles = "Admin,Manager,Employee")]
    public class PerformanceModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly ILogger<PerformanceModel> _logger;
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;

        public PerformanceModel(
            IOrderService orderService, 
            ILogger<PerformanceModel> logger,
            ApplicationDbContext context,
            IEncryptionService encryptionService)
        {
            _orderService = orderService;
            _logger = logger;
            _context = context;
            _encryptionService = encryptionService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // Check if the user is authenticated before proceeding
            if (!User.Identity.IsAuthenticated)
            {
                _logger.LogWarning("Unauthorized access attempt to performance data");
                Response.StatusCode = 401; // Unauthorized
                return new JsonResult(new { error = "Unauthorized access" });
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
                Response.StatusCode = 403; // Forbidden
                return new JsonResult(new { error = "Access denied. Insufficient permissions." });
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
                    customerName = GetDecryptedCustomerName(order.User),
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
                return new JsonResult(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching store performance data");
                Response.StatusCode = 500;
                return new JsonResult(new { error = "Failed to fetch store performance data" });
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

        private string GetDecryptedCustomerName(ApplicationUser user)
        {
            if (user == null)
                return "Anonymous";
                
            try
            {
                // Try to use FullName first
                if (!string.IsNullOrEmpty(user.FullName))
                {
                    try {
                        return _encryptionService.Decrypt(user.FullName);
                    } catch {
                        // If decryption fails, use the original value
                        return user.FullName;
                    }
                }
                
                // Fall back to UserName
                if (!string.IsNullOrEmpty(user.UserName))
                {
                    try {
                        return _encryptionService.Decrypt(user.UserName);
                    } catch {
                        // If decryption fails, use the original value
                        return user.UserName;
                    }
                }
                
                // Fall back to Email
                if (!string.IsNullOrEmpty(user.Email))
                {
                    try {
                        return _encryptionService.Decrypt(user.Email);
                    } catch {
                        // If decryption fails, use the original value
                        return user.Email;
                    }
                }
                
                return "Anonymous";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Failed to decrypt name for user {user.Id}");
                return "Customer";
            }
        }
    }
} 