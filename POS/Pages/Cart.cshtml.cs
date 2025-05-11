using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Pages
{
    [Authorize]
    public class CartModel : PageModel
    {
        private readonly ICartService _cartService;

        public CartModel(ICartService cartService)
        {
            _cartService = cartService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            return Page();
        }
    }
} 