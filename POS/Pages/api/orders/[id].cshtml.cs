using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Pages.api.orders
{
    [Authorize(Roles = "Admin,Manager")]
    public class OrderDetailsModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly ILogger<OrderDetailsModel> _logger;

        public OrderDetailsModel(IOrderService orderService, ILogger<OrderDetailsModel> logger)
        {
            _orderService = orderService;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync(int id)
        {
            // Check if the user is authenticated before proceeding
            if (!User.Identity.IsAuthenticated)
            {
                Response.StatusCode = 401; // Unauthorized
                return new JsonResult(new { error = "Unauthorized access" });
            }

            // Check if the user has the required role
            if (!User.IsInRole("Manager") && !User.IsInRole("Admin"))
            {
                Response.StatusCode = 403; // Forbidden
                return new JsonResult(new { error = "Access denied. Insufficient permissions." });
            }
            
            try
            {
                _logger.LogInformation($"Fetching order details for order ID: {id}");
                
                // Get the order by ID
                var order = await _orderService.GetOrderByIdAsync(id);
                
                if (order == null)
                {
                    Response.StatusCode = 404;
                    return new JsonResult(new { error = "Order not found" });
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
                
                return new JsonResult(formattedOrder);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error fetching order details for order ID: {id}");
                Response.StatusCode = 500;
                return new JsonResult(new { error = "Failed to fetch order details" });
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