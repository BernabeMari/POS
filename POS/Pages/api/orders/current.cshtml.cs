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
    [Authorize(Roles = "Employee")]
    public class CurrentModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<CurrentModel> _logger;

        public CurrentModel(
            IOrderService orderService, 
            IEncryptionService encryptionService,
            ILogger<CurrentModel> logger)
        {
            _orderService = orderService;
            _encryptionService = encryptionService;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            try
            {
                _logger.LogInformation("Fetching current orders for Cashier dashboard");
                
                // Get the current employee ID
                string employeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Get new and assigned orders
                var newOrders = await _orderService.GetNewOrdersAsync();
                var assignedOrders = await _orderService.GetAssignedOrdersAsync(employeeId);
                
                // Combine both sets of orders
                var currentOrders = newOrders.Concat(assignedOrders).ToList();
                
                _logger.LogInformation($"Found {currentOrders.Count} current orders");
                
                // Return the combined list
                return new JsonResult(currentOrders);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching current orders");
                Response.StatusCode = 500;
                return new JsonResult(new { error = ex.Message });
            }
        }
    }
} 