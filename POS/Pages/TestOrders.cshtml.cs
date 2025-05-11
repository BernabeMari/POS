using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Pages
{
    [Authorize]
    public class TestOrdersModel : PageModel
    {
        private readonly IOrderService _orderService;

        public TestOrdersModel(IOrderService orderService)
        {
            _orderService = orderService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            return Page();
        }
    }
} 