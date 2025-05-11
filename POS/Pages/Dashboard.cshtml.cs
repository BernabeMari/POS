using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Antiforgery;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Pages
{
    [Authorize]
    [IgnoreAntiforgeryToken]
    public class DashboardModel : PageModel
    {
        private readonly IPageTemplateService _templateService;
        private readonly IPageElementService _elementService;
        private readonly IOrderService _orderService;

        public DashboardModel(
            IPageTemplateService templateService, 
            IPageElementService elementService,
            IOrderService orderService)
        {
            _templateService = templateService;
            _elementService = elementService;
            _orderService = orderService;
        }

        public PageTemplate ActiveTemplate { get; set; }
        public List<PageElement> ProductElements { get; set; } = new List<PageElement>();
        public List<Order> RecentOrders { get; set; } = new List<Order>();
        public string UserName { get; set; }
        
        public async Task<IActionResult> OnGetAsync()
        {
            // Get the active template for the Dashboard page
            ActiveTemplate = await _templateService.GetTemplateByNameAsync("Dashboard");
            
            // Get all available products
            ProductElements = (await _elementService.GetAvailableElementsByPageNameAsync("Dashboard"))
                .Where(e => e.ElementType == "Image")
                .ToList();
            
            // Get user's display name and ID
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            UserName = User.FindFirstValue(ClaimTypes.Name) ?? "User";
            
            // Get recent orders for the current user
            if (!string.IsNullOrEmpty(userId))
            {
                var allOrders = await _orderService.GetOrdersByUserIdAsync(userId);
                // Take only the 5 most recent orders
                RecentOrders = allOrders.OrderByDescending(o => o.CreatedAt).Take(5).ToList();
            }
            
            return Page();
        }
        
        public async Task<IActionResult> OnPostAddToCartAsync(int elementId, int quantity = 1)
        {
            if (elementId <= 0)
            {
                return BadRequest("Invalid product element ID");
            }
            
            // Validate quantity
            if (quantity <= 0)
            {
                quantity = 1; // Set to default if invalid
            }
            
            // Get the element that represents a product
            var element = await _elementService.GetElementByIdAsync(elementId);
            
            if (element == null || !element.IsProduct)
            {
                return BadRequest("Product not found");
            }
            
            // Check if the product is marked as available
            if (!element.IsAvailable)
            {
                TempData["ErrorMessage"] = "This product is currently unavailable.";
                return RedirectToPage();
            }
            
            // Check if there's enough stock
            if (element.ProductStockQuantity < quantity)
            {
                TempData["ErrorMessage"] = "Not enough stock available for the requested quantity.";
                return RedirectToPage();
            }
            
            // Create a new order for this product
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            
            var order = new Order
            {
                UserId = userId,
                ProductName = element.ProductName,
                ProductImageUrl = element.ImageUrl,
                ProductImageDescription = element.ImageDescription,
                Quantity = quantity,
                Price = element.ProductPrice,
                TotalPrice = element.ProductPrice * quantity,
                Status = OrderStatus.Pending,
                CreatedAt = DateTime.Now,
                Notes = $"Ordered from Dashboard: {element.ProductDescription}"
            };
            
            try
            {
                // Use the new method that handles order creation and stock updates together
                var createdOrder = await _orderService.CreateOrderAndUpdateStockAsync(order, element);
                
                // Redirect to the success page
                return RedirectToPage("/OrderSuccess", new { orderId = createdOrder.Id });
            }
            catch (Exception ex)
            {
                // Log the error
                TempData["ErrorMessage"] = $"An error occurred while processing your order: {ex.Message}";
                return RedirectToPage();
            }
        }
        
        public async Task<IActionResult> OnPostCheckOrderStatusAsync([FromBody] OrderStatusRequest request)
        {
            if (request?.OrderIds == null || !request.OrderIds.Any())
            {
                return new JsonResult(new { success = false, message = "No order IDs provided" });
            }
            
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return new JsonResult(new { success = false, message = "User not authenticated" });
            }
            
            var orderUpdates = new List<OrderStatusUpdate>();
            
            foreach (var orderId in request.OrderIds)
            {
                var order = await _orderService.GetOrderByIdAsync(orderId);
                
                // Only include orders that belong to the current user for security
                if (order != null && order.UserId == userId)
                {
                    orderUpdates.Add(new OrderStatusUpdate
                    {
                        Id = order.Id,
                        Status = order.Status.ToString()
                    });
                }
            }
            
            return new JsonResult(new { success = true, orders = orderUpdates });
        }
    }
    
    public class OrderStatusRequest
    {
        public List<int> OrderIds { get; set; } = new List<int>();
    }
    
    public class OrderStatusUpdate
    {
        public int Id { get; set; }
        public string Status { get; set; }
    }
} 