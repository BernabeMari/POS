using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Text.Json;

namespace POS.Pages.api.products
{
    public class ProductByIdModel : PageModel
    {
        private readonly IProductService _productService;

        public ProductByIdModel(IProductService productService)
        {
            _productService = productService;
        }

        public async Task<IActionResult> OnGetAsync(int id)
        {
            try
            {
                // Get product by id
                var product = await _productService.GetProductByIdAsync(id);
                
                if (product == null)
                {
                    return new NotFoundResult();
                }
                
                // Return as JSON
                return new JsonResult(new {
                    id = product.Id,
                    name = product.Name,
                    description = product.Description,
                    price = product.Price,
                    imageUrl = product.ImageUrl,
                    imageDescription = product.ImageDescription,
                    stockQuantity = product.StockQuantity,
                    isAvailable = product.IsAvailable,
                    stock = product.StockQuantity // Added for compatibility with the frontend
                });
            }
            catch (Exception ex)
            {
                // Return error
                return new JsonResult(new { error = "Error retrieving product: " + ex.Message })
                {
                    StatusCode = 500
                };
            }
        }
    }
} 