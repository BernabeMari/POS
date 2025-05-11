using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Data;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;

namespace POS.Areas.Employee.Pages.Cashier
{
    [Authorize(Roles = "Employee")]
    public class IndexModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly IProductService _productService;
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(
            IOrderService orderService, 
            IProductService productService,
            ApplicationDbContext context,
            IEncryptionService encryptionService,
            ILogger<IndexModel> logger)
        {
            _orderService = orderService;
            _productService = productService;
            _context = context;
            _encryptionService = encryptionService;
            _logger = logger;
        }

        [TempData]
        public string StatusMessage { get; set; }

        public string EmployeeId { get; set; }
        public string FullName { get; set; }
        public string PositionName { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // Get the current employee ID
            EmployeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Check if user is in Employee role
            if (!User.IsInRole("Employee"))
            {
                return RedirectToPage("/Index");
            }

            // Check if user has the Cashier position
            var user = await _context.Users
                .Include(u => u.Position)
                .FirstOrDefaultAsync(u => u.Id == EmployeeId);
                
            if (user?.Position?.Name != "Cashier")
            {
                // Redirect to the appropriate dashboard based on position
                if (user?.Position?.Name == "Manager")
                {
                    return RedirectToPage("/Manager/Index", new { area = "Employee" });
                }
                else if (user?.Position?.Name == "Assistant Manager")
                {
                    return RedirectToPage("/AssistantManager/Index", new { area = "Employee" });
                }
                else if (user?.Position?.Name == "Inventory Clerk")
                {
                    return RedirectToPage("/InventoryClerk/Index", new { area = "Employee" });
                }
                else
                {
                    return RedirectToPage("/Index", new { area = "Employee" });
                }
            }

            // Get the username, attempt to decrypt if needed
            string username = User.Identity?.Name ?? "Unknown";
            try
            {
                // If the claims transformation didn't already handle this
                if (IsValidBase64(username))
                {
                    username = _encryptionService.Decrypt(username);
                    _logger.LogInformation($"Decrypted username on Cashier page: {username}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Failed to decrypt username: {username}");
            }

            FullName = username;
            PositionName = user?.Position?.Name ?? "Cashier";

            return Page();
        }
        
        // Helper method to check if a string is valid Base64
        private bool IsValidBase64(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;
                
            try
            {
                Convert.FromBase64String(input);
                return true;
            }
            catch
            {
                return false;
            }
        }
        
        // Handle order completion
        public async Task<IActionResult> OnPostCompleteOrderAsync(int orderId)
        {
            if (orderId <= 0)
            {
                return BadRequest("Invalid order ID");
            }
            
            try
            {
                // Get the current employee ID
                var employeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // First check if this order is assigned to this employee
                var order = await _orderService.GetOrderByIdAsync(orderId);
                
                if (order == null)
                {
                    return new JsonResult(new { success = false, message = "Order not found" });
                }
                
                if (order.AssignedToEmployeeId != employeeId && order.AssignedToEmployeeId != null)
                {
                    return new JsonResult(new { success = false, message = "You are not authorized to complete this order" });
                }
                
                // Use CompleteOrderAsync to ensure stock is deducted properly
                var completedOrder = await _orderService.CompleteOrderAsync(orderId);
                
                if (completedOrder != null)
                {
                    StatusMessage = $"Order #{orderId} has been marked as completed and ingredient stock has been updated.";
                    return new JsonResult(new { success = true, message = StatusMessage });
                }
                else
                {
                    return new JsonResult(new { success = false, message = "Failed to complete the order." });
                }
            }
            catch (Exception ex)
            {
                return new JsonResult(new { success = false, message = ex.Message });
            }
        }
        
        // Handle order status update
        public async Task<IActionResult> OnPostUpdateStatusAsync(int orderId, OrderStatus status)
        {
            if (orderId <= 0)
            {
                return BadRequest("Invalid order ID");
            }
            
            try
            {
                // Get the current employee ID
                var employeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // First check if this order is assigned to this employee or unassigned
                var order = await _orderService.GetOrderByIdAsync(orderId);
                
                if (order == null)
                {
                    return new JsonResult(new { success = false, message = "Order not found" });
                }
                
                if (order.AssignedToEmployeeId != employeeId && order.AssignedToEmployeeId != null)
                {
                    return new JsonResult(new { success = false, message = "You are not authorized to update this order" });
                }
                
                // If trying to complete, redirect to complete method which handles stock deduction
                if (status == OrderStatus.Completed || status == OrderStatus.Complete)
                {
                    return await OnPostCompleteOrderAsync(orderId);
                }
                
                // Otherwise, update the status normally
                var updatedOrder = await _orderService.UpdateOrderStatusAsync(orderId, status);
                
                if (updatedOrder != null)
                {
                    StatusMessage = $"Order #{orderId} status has been updated to {status}.";
                    return new JsonResult(new { success = true, message = StatusMessage });
                }
                else
                {
                    return new JsonResult(new { success = false, message = "Failed to update order status." });
                }
            }
            catch (Exception ex)
            {
                return new JsonResult(new { success = false, message = ex.Message });
            }
        }
    }
} 