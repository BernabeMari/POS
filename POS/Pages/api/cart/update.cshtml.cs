using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Pages.api.cart
{
    [Authorize]
    public class UpdateModel : PageModel
    {
        private readonly ICartService _cartService;

        public UpdateModel(ICartService cartService)
        {
            _cartService = cartService;
        }
        
        public class CartUpdateRequest
        {
            public int CartItemId { get; set; }
            public int Quantity { get; set; }
        }
        
        public object Result { get; private set; }

        public async Task<IActionResult> OnPostAsync([FromBody] CartUpdateRequest request)
        {
            try
            {
                if (request == null || request.CartItemId <= 0)
                {
                    return BadRequest(new { success = false, message = "Invalid cart item ID" });
                }
                
                if (request.Quantity <= 0)
                {
                    return BadRequest(new { success = false, message = "Quantity must be greater than 0" });
                }
                
                // Get the current user ID
                string userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Get the cart item
                var cartItem = await _cartService.GetCartItemByIdAsync(request.CartItemId);
                
                // Check if cart item exists and belongs to the current user
                if (cartItem == null || cartItem.UserId != userId)
                {
                    return BadRequest(new { success = false, message = "Cart item not found" });
                }
                
                // Update quantity
                cartItem.Quantity = request.Quantity;
                cartItem.UpdatedAt = DateTime.Now;
                
                // Save to database
                await _cartService.UpdateCartItemAsync(cartItem);
                
                // Get updated cart count and total
                var cartCount = await _cartService.GetCartItemCountAsync(userId);
                var cartTotal = await _cartService.GetCartTotalAsync(userId);
                
                // Return success response
                return new JsonResult(new { 
                    success = true, 
                    cartCount = cartCount,
                    cartTotal = cartTotal,
                    message = "Cart updated successfully"
                });
            }
            catch (Exception ex)
            {
                // Return error response
                return new JsonResult(new { 
                    success = false, 
                    message = "Error updating cart: " + ex.Message 
                });
            }
        }
    }
} 