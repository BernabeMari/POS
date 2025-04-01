using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using POS.Models;
using POS.Services;
using System.Text.Json;

namespace POS.Pages.api.orders
{
    [Authorize] // Allow any authenticated user temporarily for testing
    public class NewModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly ILogger<NewModel> _logger;

        public NewModel(IOrderService orderService, ILogger<NewModel> logger)
        {
            _orderService = orderService;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            try
            {
                _logger.LogInformation("Fetching new orders for Employee dashboard");
                
                // Get new, unassigned orders
                var newOrders = await _orderService.GetNewOrdersAsync();
                
                // Log some info about what we found
                _logger.LogInformation($"Found {newOrders.Count()} new orders");
                
                return new JsonResult(newOrders);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching new orders");
                Response.StatusCode = 500;
                return new JsonResult(new { error = ex.Message });
            }
        }
    }
} 