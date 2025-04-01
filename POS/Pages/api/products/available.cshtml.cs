using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Text.Json;

namespace POS.Pages.api.products
{
    public class AvailableModel : PageModel
    {
        private readonly IProductService _productService;

        public AvailableModel(IProductService productService)
        {
            _productService = productService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            try
            {
                // Get all available products
                var products = await _productService.GetAvailableProductsAsync();
                
                // Return as JSON
                return new JsonResult(products.Select(p => new {
                    id = p.Id,
                    name = p.Name,
                    description = p.Description,
                    price = p.Price,
                    imageUrl = p.ImageUrl,
                    imageDescription = p.ImageDescription,
                    stockQuantity = p.StockQuantity
                }));
            }
            catch (Exception ex)
            {
                // Return error
                return new JsonResult(new { error = "Error retrieving products: " + ex.Message })
                {
                    StatusCode = 500
                };
            }
        }
    }
} 