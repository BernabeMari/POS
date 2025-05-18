using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Data;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;

namespace POS.Areas.Employee.Pages.InventoryClerk
{
    [Authorize(Roles = "Employee")]
    public class IndexModel : PageModel
    {
        private readonly IOrderService _orderService;
        private readonly IProductService _productService;
        private readonly ApplicationDbContext _context;

        public IndexModel(
            IOrderService orderService, 
            IProductService productService,
            ApplicationDbContext context)
        {
            _orderService = orderService;
            _productService = productService;
            _context = context;
        }

        [TempData]
        public string StatusMessage { get; set; }

        public string EmployeeId { get; set; }
        public string FullName { get; set; }
        public string PositionName { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // Get the current employee ID
            EmployeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Check if user is in Employee role
            if (!User.IsInRole("Employee"))
            {
                return RedirectToPage("/Index");
            }

            // Check if user has the Inventory Clerk position
            var user = await _context.Users
                .Include(u => u.Position)
                .FirstOrDefaultAsync(u => u.Id == EmployeeId);
                
            if (user?.Position?.Name != "Inventory Clerk")
            {
                // Redirect to the appropriate dashboard based on position
                if (user?.Position?.Name == "Manager")
                {
                    return RedirectToPage("/Manager/Index", new { area = "Employee" });
                }
                else if (user?.Position?.Name == "Assistant Manager")
                {
                    return RedirectToPage("/AssistantManager/Index", new { area = "Employee" });
                }
                else
                {
                    return RedirectToPage("/Index", new { area = "Employee" });
                }
            }

            FullName = User.Identity?.Name ?? "Inventory Clerk";
            PositionName = user?.Position?.Name ?? "Inventory Clerk";

            return Page();
        }
        
        public class UpdateQuantityRequest
        {
            public int ProductId { get; set; }
            public int NewQuantity { get; set; }
            public string Reason { get; set; }
            public string Notes { get; set; }
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostUpdateQuantityAsync([FromBody] UpdateQuantityRequest request)
        {
            // Get the current employee ID for audit tracking
            EmployeeId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            
            // Validate request
            if (request == null || request.ProductId <= 0)
            {
                return BadRequest("Invalid product data");
            }
            
            try
            {
                // Find the product
                var product = await _context.Products.FindAsync(request.ProductId);
                if (product == null)
                {
                    return NotFound("Product not found");
                }
                
                // Record the old quantity for the audit log
                var oldQuantity = product.StockQuantity;
                
                // Update the product quantity
                product.StockQuantity = request.NewQuantity;
                
                // Check if the product is now low on stock
                bool isLowStock = product.StockQuantity < product.ReorderThreshold;
                
                // Save the changes
                await _context.SaveChangesAsync();
                
                // Create an inventory audit log entry
                var inventoryLog = new InventoryLog
                {
                    ProductId = product.Id,
                    PreviousQuantity = oldQuantity,
                    NewQuantity = request.NewQuantity,
                    ChangeReason = request.Reason,
                    Notes = request.Notes,
                    UserId = EmployeeId,
                    Timestamp = DateTime.Now
                };
                
                _context.InventoryLogs.Add(inventoryLog);
                await _context.SaveChangesAsync();
                
                // Return a success result with updated product details
                return new JsonResult(new { 
                    success = true, 
                    productId = product.Id, 
                    newQuantity = product.StockQuantity,
                    isLowStock = isLowStock
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Failed to update product quantity: {ex.Message}");
            }
        }
    }
} 