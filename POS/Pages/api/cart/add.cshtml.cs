using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Pages.api.cart
{
    [Authorize]
    public class AddModel : PageModel
    {
        private readonly ICartService _cartService;
        private readonly IProductService _productService;
        private readonly ILogger<AddModel> _logger;

        public AddModel(ICartService cartService, IProductService productService, ILogger<AddModel> logger)
        {
            _cartService = cartService;
            _productService = productService;
            _logger = logger;
        }
        
        public class CartAddRequest
        {
            public int ProductId { get; set; }
            public string ProductName { get; set; }
            public string ProductImageUrl { get; set; }
            public string ProductImageDescription { get; set; }
            public decimal Price { get; set; }
            public int Quantity { get; set; } = 1;
        }
        
        public object Result { get; private set; }

        public async Task<IActionResult> OnPostAsync([FromBody] CartAddRequest request)
        {
            try
            {
                if (request == null)
                {
                    return BadRequest(new { success = false, message = "Invalid request data" });
                }
                
                // Get the current user ID
                string userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                _logger.LogInformation($"Adding to cart for user ID: {userId}");
                
                // If the request has a productId, fetch the product from the database
                // to ensure all product information is accurate
                Product product = null;
                if (request.ProductId > 0)
                {
                    _logger.LogInformation($"Fetching product with ID: {request.ProductId}");
                    product = await _productService.GetProductByIdAsync(request.ProductId);
                    if (product == null)
                    {
                        _logger.LogWarning($"Product not found with ID: {request.ProductId}");
                        // If product ID is provided but not found, we'll continue with the provided details
                        // This allows adding custom products not in the database
                    }
                    else
                    {
                        // Check if product is available
                        if (!product.IsAvailable)
                        {
                            return BadRequest(new { success = false, message = "Product is not available" });
                        }
                    }
                }
                
                // Create the cart item
                var cartItem = new CartItem
                {
                    UserId = userId,
                    ProductId = product?.Id ?? (request.ProductId > 0 ? request.ProductId : null),
                    ProductName = product?.Name ?? request.ProductName,
                    ProductImageUrl = product?.ImageUrl ?? request.ProductImageUrl,
                    ProductImageDescription = product?.ImageDescription ?? request.ProductImageDescription ?? "",
                    Quantity = request.Quantity,
                    Price = product?.Price ?? request.Price,
                    CreatedAt = DateTime.Now
                };
                
                _logger.LogInformation($"Cart item created: {System.Text.Json.JsonSerializer.Serialize(cartItem)}");
                
                // Save to database
                var addedItem = await _cartService.AddToCartAsync(cartItem);
                
                // Get updated cart count
                var cartCount = await _cartService.GetCartItemCountAsync(userId);
                
                // Return success response
                return new JsonResult(new { 
                    success = true, 
                    cartItemId = addedItem.Id,
                    cartCount = cartCount,
                    message = "Item added to cart successfully"
                });
            }
            catch (Exception ex)
            {
                // Log the full exception details
                _logger.LogError(ex, "Error adding item to cart");
                
                // Capture inner exception details if available
                string errorMessage = ex.Message;
                if (ex.InnerException != null)
                {
                    errorMessage += " Inner exception: " + ex.InnerException.Message;
                }
                
                // Return error response with more details
                return new JsonResult(new { 
                    success = false, 
                    message = "Error adding item to cart: " + errorMessage
                });
            }
        }
    }
} 