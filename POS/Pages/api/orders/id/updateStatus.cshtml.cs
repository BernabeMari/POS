using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using System.Text.Json;

namespace POS.Pages.api.orders.id
{
    [Authorize(Roles = "Employee,Admin")]
    public class UpdateStatusModel : PageModel
    {
        private readonly IOrderService _orderService;

        public UpdateStatusModel(IOrderService orderService)
        {
            _orderService = orderService;
        }
        
        public class StatusUpdateRequest
        {
            public string Status { get; set; }
        }

        public async Task<IActionResult> OnPostAsync(int id, [FromBody] StatusUpdateRequest request)
        {
            try
            {
                if (request == null || string.IsNullOrEmpty(request.Status))
                {
                    return BadRequest(new { success = false, message = "Status is required" });
                }
                
                // Get the current employee ID
                string employeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Get the order
                var order = await _orderService.GetOrderByIdAsync(id);
                
                if (order == null)
                {
                    return NotFound(new { success = false, message = "Order not found" });
                }
                
                // Parse the status string to enum
                if (!Enum.TryParse<OrderStatus>(request.Status, true, out var newStatus))
                {
                    return BadRequest(new { success = false, message = "Invalid status value" });
                }
                
                // If the order is not yet assigned to an employee, assign it first
                if (order.AssignedToEmployeeId == null)
                {
                    order = await _orderService.AssignOrderToEmployeeAsync(id, employeeId);
                }
                else if (order.AssignedToEmployeeId != employeeId)
                {
                    // Check if the employee is allowed to update this order
                    // For simplicity, we allow any employee to update any order, but you might want to restrict this
                }
                
                // Update the status
                order = await _orderService.UpdateOrderStatusAsync(id, newStatus);
                
                // Return success response
                return new JsonResult(new { 
                    success = true, 
                    orderId = order.Id,
                    status = order.Status.ToString(),
                    message = "Order status updated successfully"
                });
            }
            catch (Exception ex)
            {
                // Return error response
                return new JsonResult(new { 
                    success = false, 
                    message = "Error updating order status: " + ex.Message 
                });
            }
        }
    }
} 