using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using System.Text.Json;

namespace POS.Pages.api.orders
{
    [Authorize]
    public class UserModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly ILogger<UserModel> _logger;

        public UserModel(IOrderService orderService, ILogger<UserModel> logger)
        {
            _orderService = orderService;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            try
            {
                // Get the current user ID
                string userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                _logger.LogInformation($"Fetching orders for user {userId}");
                
                // Get orders for this user
                var userOrders = await _orderService.GetOrdersByUserIdAsync(userId);
                
                _logger.LogInformation($"Found {userOrders.Count()} orders for user {userId}");
                
                return new JsonResult(userOrders);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching user orders");
                Response.StatusCode = 500;
                return new JsonResult(new { error = ex.Message });
            }
        }
    }
} 