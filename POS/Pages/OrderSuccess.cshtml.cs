using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;

namespace POS.Pages
{
    [Authorize]
    public class OrderSuccessModel : PageModel
    {
        private readonly IOrderService _orderService;

        public OrderSuccessModel(IOrderService orderService)
        {
            _orderService = orderService;
        }

        public Order Order { get; set; }
        
        public async Task<IActionResult> OnGetAsync(int orderId)
        {
            if (orderId <= 0)
            {
                return RedirectToPage("/Dashboard");
            }
            
            // Get order details
            Order = await _orderService.GetOrderByIdAsync(orderId);
            
            if (Order == null)
            {
                return NotFound("Order not found");
            }
            
            return Page();
        }
    }
} 