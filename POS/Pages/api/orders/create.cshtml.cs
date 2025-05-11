using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using POS.Data;
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
        private readonly IPageElementService _pageElementService;
        private readonly ApplicationDbContext _context;

        public CreateModel(IOrderService orderService, IProductService productService, IPageElementService pageElementService, ApplicationDbContext context)
        {
            _orderService = orderService;
            _productService = productService;
            _pageElementService = pageElementService;
            _context = context;
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
                PageElement productElement = null;
                
                if (request.ProductId > 0)
                {
                    // First check if this is a page element product
                    productElement = await _pageElementService.GetElementByIdAsync(request.ProductId);
                    
                    if (productElement != null)
                    {
                        if (!productElement.IsProduct)
                        {
                            return BadRequest(new { success = false, message = "Element is not a product" });
                        }
                        
                        // Check if the product is marked as available
                        if (!productElement.IsAvailable)
                        {
                            return BadRequest(new { success = false, message = "This product is currently unavailable" });
                        }
                        
                        // Check if page element product has enough stock
                        if (productElement.ProductStockQuantity < request.Quantity)
                        {
                            return BadRequest(new { success = false, message = "Not enough stock available" });
                        }
                        
                        // Check if it's been marked as disabled due to low ingredient stock
                        bool isDisabled = false;
                        
                        if (productElement.Ingredients != null && productElement.Ingredients.Any())
                        {
                            // Check if any ingredients are low on stock
                            foreach (var ingredient in productElement.Ingredients)
                            {
                                var stock = await _context.Stocks
                                    .FirstOrDefaultAsync(s => s.ProductName.ToLower() == ingredient.IngredientName.ToLower());
                                
                                if (stock != null && stock.Quantity <= stock.ThresholdLevel)
                                {
                                    isDisabled = true;
                                    return BadRequest(new { 
                                        success = false, 
                                        message = $"This product is unavailable due to low stock of {ingredient.IngredientName}"
                                    });
                                }
                            }
                        }
                    }
                    else
                    {
                        // If not a page element product, check regular products
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
                }
                
                // Create the order
                var order = new Order
                {
                    UserId = userId,
                    ProductName = productElement?.ProductName ?? product?.Name ?? request.ProductName,
                    ProductImageUrl = productElement?.ImageUrl ?? product?.ImageUrl ?? request.ProductImageUrl,
                    ProductImageDescription = productElement?.ImageDescription ?? product?.ImageDescription ?? request.ProductImageDescription ?? "",
                    Quantity = request.Quantity,
                    Notes = request.Notes,
                    Price = productElement?.ProductPrice ?? product?.Price ?? request.Price,
                    TotalPrice = (productElement?.ProductPrice ?? product?.Price ?? request.Price) * request.Quantity,
                    Status = OrderStatus.Pending,
                    CreatedAt = DateTime.Now
                };
                
                // Save to database and update stock if applicable
                Order createdOrder;
                
                if (productElement != null && productElement.IsProduct && productElement.Ingredients != null && productElement.Ingredients.Any())
                {
                    // If we have a page element with ingredients, use the method that also updates stock
                    createdOrder = await _orderService.CreateOrderAndUpdateStockAsync(order, productElement);
                }
                else
                {
                    // Otherwise use the regular create method
                    createdOrder = await _orderService.CreateOrderAsync(order);
                }
                
                // Return success response
                return new JsonResult(new { 
                    success = true, 
                    orderId = createdOrder.Id,
                    message = "Order created successfully"
                });
            }
            catch (Exception ex)
            {
                // Return detailed error response
                return new JsonResult(new { 
                    success = false, 
                    message = "Error creating order: " + ex.Message,
                    stackTrace = ex.StackTrace // Include stack trace for debugging
                });
            }
        }
    }
} 