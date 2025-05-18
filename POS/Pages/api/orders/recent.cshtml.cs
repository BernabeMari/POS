using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using POS.Data;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using System.Text.Json;

namespace POS.Pages.api.orders
{
    [Authorize(Roles = "Employee,Admin")]
    public class RecentModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly ILogger<RecentModel> _logger;
        private readonly IEncryptionService _encryptionService;
        private readonly ApplicationDbContext _context;

        public RecentModel(
            IOrderService orderService, 
            ILogger<RecentModel> logger,
            IEncryptionService encryptionService,
            ApplicationDbContext context)
        {
            _orderService = orderService;
            _logger = logger;
            _encryptionService = encryptionService;
            _context = context;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // Check if the user is authenticated before proceeding
            if (!User.Identity.IsAuthenticated)
            {
                Response.StatusCode = 401; // Unauthorized
                return new JsonResult(new { error = "Unauthorized access" });
            }

            // Check if the user has the required role
            if (!User.IsInRole("Employee") && !User.IsInRole("Admin"))
            {
                Response.StatusCode = 403; // Forbidden
                return new JsonResult(new { error = "Access denied. Insufficient permissions." });
            }
            
            try
            {
                _logger.LogInformation("Fetching recent orders for Manager dashboard");
                
                // Get all orders (we'll format them for display)
                var orders = await _orderService.GetAllOrdersAsync();
                
                // Format the orders for the dashboard display
                var formattedOrders = orders.Take(10).Select(order => new {
                    id = order.Id,
                    customerName = GetDecryptedCustomerName(order),
                    itemCount = 1, // Consider using order items when available
                    total = $"${order.TotalPrice:F2}",
                    timeAgo = GetTimeAgo(order.CreatedAt),
                    status = order.Status.ToString()
                }).ToList();
                
                return new JsonResult(formattedOrders);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching recent orders");
                Response.StatusCode = 500;
                return new JsonResult(new { error = "Failed to fetch recent orders" });
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

        // Helper method to get decrypted customer name from an order
        private string GetDecryptedCustomerName(Order order)
        {
            if (order == null || order.User == null)
                return "Anonymous";
                
            try
            {
                // Try to use FullName first
                if (!string.IsNullOrEmpty(order.User.FullName))
                {
                    try {
                        return _encryptionService.Decrypt(order.User.FullName);
                    } catch {
                        // If decryption fails, use the original value
                        return order.User.FullName;
                    }
                }
                
                // Fall back to UserName
                if (!string.IsNullOrEmpty(order.User.UserName))
                {
                    try {
                        return _encryptionService.Decrypt(order.User.UserName);
                    } catch {
                        // If decryption fails, use the original value
                        return order.User.UserName;
                    }
                }
                
                // Fall back to Email
                if (!string.IsNullOrEmpty(order.User.Email))
                {
                    try {
                        return _encryptionService.Decrypt(order.User.Email);
                    } catch {
                        // If decryption fails, use the original value
                        return order.User.Email;
                    }
                }
                
                return "Anonymous";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Failed to decrypt name for user in order {order.Id}");
                return "Customer";
            }
        }
        
        // Helper method to check if a string might be encrypted
        private bool IsValidBase64(string input)
        {
            // For our purposes, we'll always try to decrypt
            return !string.IsNullOrEmpty(input);
        }
    }
} 