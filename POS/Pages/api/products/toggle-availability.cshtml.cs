using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Data;
using POS.Models;
using POS.Services;
using System.Text.Json;

namespace POS.Pages.api.products
{
    [Authorize(Roles = "Admin")]
    public class ToggleAvailabilityModel : PageModel
    {
        private readonly IPageElementService _elementService;
        private readonly ApplicationDbContext _context;

        public ToggleAvailabilityModel(IPageElementService elementService, ApplicationDbContext context)
        {
            _elementService = elementService;
            _context = context;
        }

        public class ToggleAvailabilityRequest
        {
            public int ElementId { get; set; }
            public bool IsAvailable { get; set; }
        }

        public async Task<IActionResult> OnPostAsync([FromBody] ToggleAvailabilityRequest request)
        {
            try
            {
                if (request == null)
                {
                    return BadRequest(new { success = false, message = "Invalid request data" });
                }

                // Get the element
                var element = await _elementService.GetElementByIdAsync(request.ElementId);
                if (element == null)
                {
                    return NotFound(new { success = false, message = "Product element not found" });
                }

                if (!element.IsProduct)
                {
                    return BadRequest(new { success = false, message = "Element is not a product" });
                }

                // Update availability
                element.IsAvailable = request.IsAvailable;
                
                try 
                {
                    await _elementService.UpdateElementAsync(element);
                }
                catch (Exception ex)
                {
                    // Log the detailed error
                    System.Diagnostics.Debug.WriteLine($"Error in UpdateElementAsync: {ex.Message}");
                    if (ex.InnerException != null)
                    {
                        System.Diagnostics.Debug.WriteLine($"Inner Exception: {ex.InnerException.Message}");
                    }
                    throw;
                }

                return new JsonResult(new
                {
                    success = true,
                    message = $"Product {(request.IsAvailable ? "is now available" : "is now unavailable")} for ordering",
                    productName = element.ProductName,
                    isAvailable = element.IsAvailable
                });
            }
            catch (Exception ex)
            {
                // Capture and log the full exception details
                string errorDetails = ex.ToString();
                System.Diagnostics.Debug.WriteLine($"Full exception details: {errorDetails}");
                
                return StatusCode(500, new { 
                    success = false, 
                    message = $"Error updating product: {ex.Message}",
                    details = ex.InnerException?.Message ?? "No additional details available"
                });
            }
        }
    }
} 