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
    public class AssignModel : PageModel
    {
        private readonly IOrderService _orderService;

        public AssignModel(IOrderService orderService)
        {
            _orderService = orderService;
        }

        public async Task<IActionResult> OnPostAsync(int id)
        {
            try
            {
                // Get the current employee ID
                string employeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Assign the order to this employee
                var order = await _orderService.AssignOrderToEmployeeAsync(id, employeeId);
                
                if (order == null)
                {
                    return new JsonResult(new { success = false, message = "Order not found or could not be assigned" });
                }
                
                return new JsonResult(new { success = true, orderId = order.Id });
            }
            catch (Exception ex)
            {
                return new JsonResult(new { success = false, message = ex.Message });
            }
        }
    }
} 