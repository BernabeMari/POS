using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using System.Text.Json;

namespace POS.Pages.api.orders
{
    [Authorize(Roles = "Employee,Admin")]
    public class LatestModel : PageModel
    {
        private readonly IOrderService _orderService;

        public LatestModel(IOrderService orderService)
        {
            _orderService = orderService;
        }

        public JsonResult OnGet(int since = 0)
        {
            try
            {
                // Get orders newer than the provided ID
                var latestOrders = _orderService.GetLatestOrdersAsync(since).Result;
                
                return new JsonResult(latestOrders);
            }
            catch (Exception ex)
            {
                Response.StatusCode = 500;
                return new JsonResult(new { error = ex.Message });
            }
        }
    }
} 