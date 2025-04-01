using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace POS.Pages.api.orders
{
    [Authorize]
    public class CreateModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly IProductService _productService;

        public CreateModel(IOrderService orderService, IProductService productService)
        {
            _orderService = orderService;
            _productService = productService;
        }
        
        public class OrderCreateRequest
        {
            public int ProductId { get; set; }
            public string ProductName { get; set; }
            public string ProductImageUrl { get; set; }
            public string ProductImageDescription { get; set; }
            public decimal Price { get; set; }
            public int Quantity { get; set; }
            public string Notes { get; set; }
        }
        
        public object Result { get; private set; }

        public async Task<IActionResult> OnPostAsync([FromBody] OrderCreateRequest request)
        {
            try
            {
                if (request == null)
                {
                    return BadRequest(new { success = false, message = "Invalid request data" });
                }
                
                // Get the current user ID
                string userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // If the request has a productId, fetch the product from the database
                // to ensure all product information is accurate
                Product product = null;
                if (request.ProductId > 0)
                {
                    product = await _productService.GetProductByIdAsync(request.ProductId);
                    if (product == null)
                    {
                        return BadRequest(new { success = false, message = "Product not found" });
                    }
                    
                    // Check if product is available
                    if (!product.IsAvailable)
                    {
                        return BadRequest(new { success = false, message = "Product is not available for order" });
                    }
                }
                
                // Create the order
                var order = new Order
                {
                    UserId = userId,
                    ProductName = product?.Name ?? request.ProductName,
                    ProductImageUrl = product?.ImageUrl ?? request.ProductImageUrl,
                    ProductImageDescription = product?.ImageDescription ?? request.ProductImageDescription ?? "",
                    Quantity = request.Quantity,
                    Notes = request.Notes,
                    Price = product?.Price ?? request.Price,
                    TotalPrice = (product?.Price ?? request.Price) * request.Quantity,
                    Status = OrderStatus.Pending,
                    CreatedAt = DateTime.Now
                };
                
                // Save to database
                var createdOrder = await _orderService.CreateOrderAsync(order);
                
                // Return success response
                return new JsonResult(new { 
                    success = true, 
                    orderId = createdOrder.Id,
                    message = "Order created successfully"
                });
            }
            catch (Exception ex)
            {
                // Return error response
                return new JsonResult(new { 
                    success = false, 
                    message = "Error creating order: " + ex.Message 
                });
            }
        }
    }
} 