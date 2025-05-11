using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using POS.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace POS.Controllers.Api
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Employee")]
    public class ProductsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public ProductsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: api/products
        [HttpGet]
        public async Task<ActionResult<IEnumerable<object>>> GetProducts()
        {
            var products = await _context.PageElements
                .Where(p => p.IsProduct)
                .Select(p => new {
                    p.Id,
                    Name = p.ProductName,
                    Description = p.ProductDescription,
                    Price = p.ProductPrice,
                    StockQuantity = p.ProductStockQuantity,
                    Unit = "each", // Default unit or you can add this to PageElements
                    ReorderThreshold = 5, // Default threshold or you can add this to PageElements
                    Category = "General", // Default category
                    CategoryId = 1, // Default category ID
                    Status = p.ProductStockQuantity <= 0 ? "Out of Stock" : 
                            p.ProductStockQuantity < 5 ? "Low Stock" : "In Stock"
                })
                .ToListAsync();

            return Ok(products);
        }

        // POST: api/products/updateQuantity
        [HttpPost("updateQuantity")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateQuantity([FromBody] UpdateQuantityRequest request)
        {
            // Get the current user ID for audit tracking
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            
            // Validate request
            if (request == null || request.ProductId <= 0)
            {
                return BadRequest("Invalid product data");
            }
            
            try
            {
                // Find the product in PageElements
                var product = await _context.PageElements.FindAsync(request.ProductId);
                if (product == null || !product.IsProduct)
                {
                    return NotFound("Product not found");
                }
                
                // Record the old quantity for the audit log
                var oldQuantity = product.ProductStockQuantity;
                
                // Update the product quantity
                product.ProductStockQuantity = request.NewQuantity;
                
                // Check if the product is now low on stock
                bool isLowStock = product.ProductStockQuantity < 5; // Using default threshold
                
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
                    UserId = userId,
                    Timestamp = DateTime.Now
                };
                
                _context.InventoryLogs.Add(inventoryLog);
                await _context.SaveChangesAsync();
                
                // Return a success result with updated product details
                return Ok(new { 
                    success = true, 
                    productId = product.Id, 
                    newQuantity = product.ProductStockQuantity,
                    isLowStock = isLowStock
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Failed to update product quantity: {ex.Message}");
            }
        }
        
        public class UpdateQuantityRequest
        {
            public int ProductId { get; set; }
            public int NewQuantity { get; set; }
            public string Reason { get; set; }
            public string Notes { get; set; }
        }

        // GET: api/products/by-element-id/{elementId}
        [HttpGet("by-element-id/{elementId}")]
        [AllowAnonymous] // Allow unauthenticated access since users need this
        public async Task<ActionResult> GetProductDetailsByElementId(string elementId)
        {
            try
            {
                // Sanitize the elementId to prevent SQL injection
                string sanitizedElementId = SqlInputSanitizer.SanitizeString(elementId);
                
                if (string.IsNullOrEmpty(sanitizedElementId))
                {
                    return BadRequest("Invalid element ID");
                }

                // Look up the element by its ElementId (not the primary key Id)
                var element = await _context.PageElements
                    .Include(p => p.Ingredients)
                    .FirstOrDefaultAsync(p => p.ElementId == sanitizedElementId);

                if (element == null)
                {
                    // Try looking up by the primary key as fallback (if elementId is a number)
                    if (int.TryParse(sanitizedElementId, out int id))
                    {
                        element = await _context.PageElements
                            .Include(p => p.Ingredients)
                            .FirstOrDefaultAsync(p => p.Id == id);
                    }
                }

                if (element == null)
                {
                    return NotFound($"No element found with ID {sanitizedElementId}");
                }

                // Check if any ingredients are low on stock
                bool isDisabled = false;
                string disabledReason = "";
                
                if (element.Ingredients != null && element.Ingredients.Any())
                {
                    foreach (var ingredient in element.Ingredients)
                    {
                        // Sanitize ingredient name before using in query
                        string sanitizedIngredientName = SqlInputSanitizer.SanitizeString(ingredient.IngredientName.ToLower());
                        
                        // Find the stock for this ingredient
                        var stock = await _context.Stocks
                            .FirstOrDefaultAsync(s => s.ProductName.ToLower() == sanitizedIngredientName);
                            
                        if (stock == null || stock.Quantity <= 0)
                        {
                            // Ingredient not in stock or completely out of stock
                            isDisabled = true;
                            disabledReason = $"Ingredient {SqlInputSanitizer.SanitizeString(ingredient.IngredientName)} not available in stock";
                            
                            // Update the product availability flag
                            if (element.IsAvailable)
                            {
                                element.IsAvailable = false;
                                await _context.SaveChangesAsync();
                            }
                            
                            break;
                        }
                        else if (stock.Quantity <= stock.ThresholdLevel)
                        {
                            // Low stock found
                            isDisabled = true;
                            disabledReason = $"Low stock of {SqlInputSanitizer.SanitizeString(ingredient.IngredientName)}";
                            break;
                        }
                    }
                }
                
                // If all ingredients are in stock but product was previously marked unavailable, make it available again
                if (!isDisabled && !element.IsAvailable)
                {
                    element.IsAvailable = true;
                    await _context.SaveChangesAsync();
                }

                // Return product details even if IsProduct flag is not set
                // This accommodates existing elements that may not have the flag properly set
                var productDetails = new
                {
                    // Always use the product-specific columns as primary source
                    productName = element.ProductName,
                    productDescription = element.ProductDescription,
                    productPrice = element.ProductPrice,
                    // Include alternative property names for compatibility
                    name = element.ProductName,
                    description = element.ProductDescription,
                    price = element.ProductPrice,
                    // Include image info
                    imageUrl = element.ImageUrl,
                    isAvailable = element.IsAvailable,
                    isDisabled = isDisabled || !element.IsAvailable,
                    disabledReason = !element.IsAvailable ? 
                        "This product is currently unavailable" : 
                        disabledReason
                };

                return Ok(productDetails);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error retrieving product details: {ex.Message}");
            }
        }
        
        // GET: api/product-details (for backward compatibility)
        [HttpGet("/api/product-details")]
        [AllowAnonymous] // Allow unauthenticated access since users need this
        public async Task<ActionResult> GetProductDetailsByQueryParam([FromQuery] string elementId)
        {
            if (string.IsNullOrEmpty(elementId))
            {
                return BadRequest("Element ID is required");
            }
            
            // Sanitize the elementId before passing it to the other method
            string sanitizedElementId = SqlInputSanitizer.SanitizeString(elementId);
            
            // Call the other endpoint to avoid code duplication
            return await GetProductDetailsByElementId(sanitizedElementId);
        }
    }
}