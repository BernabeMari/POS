using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Services;
using System.Security.Claims;

namespace POS.Pages.api.cart
{
    [Authorize]
    public class ClearModel : PageModel
    {
        private readonly ICartService _cartService;

        public ClearModel(ICartService cartService)
        {
            _cartService = cartService;
        }
        
        public object Result { get; private set; }

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                // Get the current user ID
                string userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Clear the cart
                await _cartService.ClearCartAsync(userId);
                
                // Return success response
                return new JsonResult(new { 
                    success = true, 
                    cartCount = 0,
                    cartTotal = 0,
                    message = "Cart cleared successfully"
                });
            }
            catch (Exception ex)
            {
                // Return error response
                return new JsonResult(new { 
                    success = false, 
                    message = "Error clearing cart: " + ex.Message 
                });
            }
        }
    }
} 