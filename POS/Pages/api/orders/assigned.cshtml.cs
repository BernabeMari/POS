using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using System.Text.Json;

namespace POS.Pages.api.orders
{
    [Authorize(Roles = "Employee")]
    public class AssignedModel : PageModel
    {
        private readonly IOrderService _orderService;

        public AssignedModel(IOrderService orderService)
        {
            _orderService = orderService;
        }

        public JsonResult OnGet()
        {
            try
            {
                // Get the current employee ID
                string employeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Get assigned orders for this employee
                var assignedOrders = _orderService.GetAssignedOrdersAsync(employeeId).Result;
                
                return new JsonResult(assignedOrders);
            }
            catch (Exception ex)
            {
                Response.StatusCode = 500;
                return new JsonResult(new { error = ex.Message });
            }
        }
    }
} 