using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Pages
{
    [Authorize]
    public class MyOrdersModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly IPageTemplateService _templateService;

        public MyOrdersModel(IOrderService orderService, IPageTemplateService templateService)
        {
            _orderService = orderService;
            _templateService = templateService;
        }

        public List<Order> Orders { get; set; } = new List<Order>();
        public PageElement? OrdersTableElement { get; set; }
        public PageElement? BackButtonElement { get; set; }
        public string BackgroundColor { get; set; } = "#ffffff";
        
        public async Task<IActionResult> OnGetAsync()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            
            // Get orders for the current user
            var orders = await _orderService.GetOrdersByUserIdAsync(userId);
            Orders = orders.OrderByDescending(o => o.CreatedAt).ToList();
            
            // Get template for this page
            var template = await _templateService.GetTemplateByNameAsync("MyOrders");
            if (template != null)
            {
                BackgroundColor = template.BackgroundColor;
                OrdersTableElement = template.Elements.FirstOrDefault(e => e.ElementId == "orders-table");
                BackButtonElement = template.Elements.FirstOrDefault(e => e.ElementId == "back-button");
            }
            
            return Page();
        }
        
        public async Task<IActionResult> OnPostCancelOrderAsync(int orderId)
        {
            if (orderId <= 0)
            {
                return BadRequest("Invalid order ID");
            }
            
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            
            // Get the order
            var order = await _orderService.GetOrderByIdAsync(orderId);
            
            if (order == null)
            {
                return NotFound("Order not found");
            }
            
            // Check if user owns this order
            if (order.UserId != userId)
            {
                return Forbid("You don't have permission to cancel this order");
            }
            
            // Check if order can be cancelled (only pending orders can be cancelled)
            if (order.Status != OrderStatus.Pending)
            {
                TempData["ErrorMessage"] = "Only pending orders can be cancelled.";
                return RedirectToPage();
            }
            
            // Update order status to Cancelled
            order.Status = OrderStatus.Cancelled;
            await _orderService.UpdateOrderAsync(order);
            
            TempData["SuccessMessage"] = "Order has been cancelled successfully.";
            return RedirectToPage();
        }
    }
} 