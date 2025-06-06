using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Data;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;

namespace POS.Areas.Employee.Pages.AssistantManager
{
    [Authorize(Roles = "Employee")]
    public class IndexModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly IProductService _productService;
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(
            IOrderService orderService, 
            IProductService productService,
            ApplicationDbContext context,
            IEncryptionService encryptionService,
            ILogger<IndexModel> logger)
        {
            _orderService = orderService;
            _productService = productService;
            _context = context;
            _encryptionService = encryptionService;
            _logger = logger;
        }

        [TempData]
        public string StatusMessage { get; set; }

        public string EmployeeId { get; set; }
        public string FullName { get; set; }
        public string PositionName { get; set; }
        public int CaesarShiftValue { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // Get the current employee ID
            EmployeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Check if user is in Employee role
            if (!User.IsInRole("Employee"))
            {
                return RedirectToPage("/Index");
            }

            // Check if user has the Assistant Manager position
            var user = await _context.Users
                .Include(u => u.Position)
                .FirstOrDefaultAsync(u => u.Id == EmployeeId);

            if (user?.Position?.Name != "Assistant Manager")
            {
                // Redirect to the appropriate dashboard based on position
                if (user?.Position?.Name == "Manager")
                {
                    return RedirectToPage("/Manager/Index", new { area = "Employee" });
                }
                else if (user?.Position?.Name == "Inventory Clerk")
                {
                    return RedirectToPage("/InventoryClerk/Index", new { area = "Employee" });
                }
                else
                {
                    return RedirectToPage("/Index", new { area = "Employee" });
                }
            }

            // Check if this Assistant Manager has been granted Manager dashboard access
            var hasManagerAccess = await _context.UserPreferences
                .AnyAsync(p => p.UserId == EmployeeId && p.Key == "ManagerAccess" && p.Value == "true");

            if (hasManagerAccess)
            {
                // Redirect to Manager dashboard
                return RedirectToPage("/Manager/Index", new { area = "Employee" });
            }

            // Get the username, attempt to decrypt if needed
            string username = User.Identity?.Name ?? "Unknown";
            try
            {
                // If the claims transformation didn't already handle this
                if (IsValidBase64(username))
                {
                    username = _encryptionService.Decrypt(username);
                    _logger.LogInformation($"Decrypted username on Assistant Manager page: {username}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Failed to decrypt username: {username}");
            }

            FullName = username;
            PositionName = user?.Position?.Name ?? "Assistant Manager";
            
            // Get the Caesar shift value from the encryption service
            CaesarShiftValue = _encryptionService.GetShiftValue();
            _logger.LogInformation($"Using Caesar shift value: {CaesarShiftValue}");

            return Page();
        }
        
        // Helper method to check if a string is valid Base64
        private bool IsValidBase64(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;
                
            try
            {
                Convert.FromBase64String(input);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
} 