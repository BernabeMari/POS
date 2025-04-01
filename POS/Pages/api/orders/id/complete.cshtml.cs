using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using System.Text.Json;

namespace POS.Pages.api.orders.id
{
    [Authorize(Roles = "Employee")]
    public class CompleteModel : PageModel
    {
        private readonly IOrderService _orderService;

        public CompleteModel(IOrderService orderService)
        {
            _orderService = orderService;
        }

        public async Task<IActionResult> OnPostAsync(int id)
        {
            try
            {
                // Get the current employee ID
                string employeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // First get the order to check if this employee is assigned to it
                var order = await _orderService.GetOrderByIdAsync(id);
                
                if (order == null)
                {
                    return new JsonResult(new { success = false, message = "Order not found" });
                }
                
                // Check if the order is assigned to this employee
                if (order.AssignedToEmployeeId != employeeId)
                {
                    return new JsonResult(new { success = false, message = "You are not assigned to this order" });
                }
                
                // Complete the order
                order = await _orderService.CompleteOrderAsync(id);
                
                return new JsonResult(new { success = true, orderId = order.Id });
            }
            catch (Exception ex)
            {
                return new JsonResult(new { success = false, message = ex.Message });
            }
        }
    }
} 