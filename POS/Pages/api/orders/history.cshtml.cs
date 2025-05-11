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
    public class HistoryModel : PageModel
    {
        private readonly IOrderService _orderService;

        public HistoryModel(IOrderService orderService)
        {
            _orderService = orderService;
        }

        public JsonResult OnGet()
        {
            try
            {
                // Get the current employee ID
                string employeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Get order history for this employee
                var orderHistory = _orderService.GetOrderHistoryAsync(employeeId).Result;
                
                return new JsonResult(orderHistory);
            }
            catch (Exception ex)
            {
                Response.StatusCode = 500;
                return new JsonResult(new { error = ex.Message });
            }
        }
    }
} 