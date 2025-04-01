using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Areas.Employee.Pages
{
    [Authorize(Roles = "Employee")]
    public class IndexModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly IProductService _productService;

        public IndexModel(IOrderService orderService, IProductService productService)
        {
            _orderService = orderService;
            _productService = productService;
        }

        [TempData]
        public string StatusMessage { get; set; }

        public string EmployeeId { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // Get the current employee ID
            EmployeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Check if user is in Employee role
            if (!User.IsInRole("Employee"))
            {
                return RedirectToPage("/Index");
            }

            return Page();
        }
        
        // Handle order assignment
        public async Task<IActionResult> OnPostAssignOrderAsync(int orderId)
        {
            if (orderId <= 0)
            {
                return BadRequest("Invalid order ID");
            }
            
            try
            {
                // Get the current employee ID
                var employeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Assign the order to this employee
                var updatedOrder = await _orderService.AssignOrderToEmployeeAsync(orderId, employeeId);
                
                if (updatedOrder != null)
                {
                    StatusMessage = $"Order #{orderId} has been assigned to you.";
                    return new JsonResult(new { success = true, message = StatusMessage });
                }
                else
                {
                    return new JsonResult(new { success = false, message = "Failed to assign order. It may have been assigned already." });
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
                
                // First check if this order is assigned to this employee
                var order = await _orderService.GetOrderByIdAsync(orderId);
                
                if (order == null)
                {
                    return new JsonResult(new { success = false, message = "Order not found" });
                }
                
                if (order.AssignedToEmployeeId != employeeId)
                {
                    return new JsonResult(new { success = false, message = "You are not authorized to update this order" });
                }
                
                // Update the status
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
                
                if (order.AssignedToEmployeeId != employeeId)
                {
                    return new JsonResult(new { success = false, message = "You are not authorized to complete this order" });
                }
                
                // Update the status to Complete instead of using CompleteOrderAsync
                var completedOrder = await _orderService.UpdateOrderStatusAsync(orderId, OrderStatus.Complete);
                
                if (completedOrder != null)
                {
                    StatusMessage = $"Order #{orderId} has been marked as completed.";
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
    }
} 