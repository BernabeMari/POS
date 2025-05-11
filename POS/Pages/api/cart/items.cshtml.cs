using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Pages.api.cart
{
    [Authorize]
    public class ItemsModel : PageModel
    {
        private readonly ICartService _cartService;

        public ItemsModel(ICartService cartService)
        {
            _cartService = cartService;
        }
        
        public object Result { get; private set; }

        public async Task<IActionResult> OnGetAsync()
        {
            try
            {
                // Get the current user ID
                string userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Get cart items
                var cartItems = await _cartService.GetCartItemsByUserIdAsync(userId);
                
                // Get cart total
                var cartTotal = await _cartService.GetCartTotalAsync(userId);
                
                // Return success response
                return new JsonResult(new { 
                    success = true, 
                    items = cartItems,
                    cartTotal = cartTotal
                });
            }
            catch (Exception ex)
            {
                // Return error response
                return new JsonResult(new { 
                    success = false, 
                    message = "Error retrieving cart items: " + ex.Message 
                });
            }
        }
    }
} 