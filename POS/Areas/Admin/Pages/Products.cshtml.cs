using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Hosting;
using POS.Models;
using POS.Services;
using System.ComponentModel.DataAnnotations;

namespace POS.Areas.Admin.Pages
{
    public class ProductsModel : PageModel
    {
        private readonly IProductService _productService;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public ProductsModel(IProductService productService, IWebHostEnvironment webHostEnvironment)
        {
            _productService = productService;
            _webHostEnvironment = webHostEnvironment;
        }

        public List<Product> Products { get; set; } = new List<Product>();

        [BindProperty]
        public Product NewProduct { get; set; } = new Product();

        [BindProperty]
        [Display(Name = "Product Image")]
        public IFormFile UploadedImage { get; set; }

        [TempData]
        public string SuccessMessage { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public async Task OnGetAsync()
        {
            Products = (await _productService.GetAllProductsAsync()).ToList();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                Products = (await _productService.GetAllProductsAsync()).ToList();
                return Page();
            }

            try
            {
                // Sanitize inputs
                NewProduct.Name = SqlInputSanitizer.SanitizeString(NewProduct.Name);
                NewProduct.Description = SqlInputSanitizer.SanitizeString(NewProduct.Description);
                NewProduct.ImageDescription = SqlInputSanitizer.SanitizeString(NewProduct.ImageDescription);
                
                // Handle file upload
                if (UploadedImage != null && UploadedImage.Length > 0)
                {
                    string uploadsFolder = Path.Combine(_webHostEnvironment.WebRootPath, "uploads", "products");
                    
                    // Ensure directory exists
                    if (!Directory.Exists(uploadsFolder))
                    {
                        Directory.CreateDirectory(uploadsFolder);
                    }
                    
                    // Create unique filename
                    string uniqueFileName = Guid.NewGuid().ToString() + "_" + SqlInputSanitizer.SanitizeString(UploadedImage.FileName);
                    string filePath = Path.Combine(uploadsFolder, uniqueFileName);
                    
                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        await UploadedImage.CopyToAsync(fileStream);
                    }
                    
                    // Update product image URL
                    NewProduct.ImageUrl = "/uploads/products/" + uniqueFileName;
                }

                await _productService.CreateProductAsync(NewProduct);
                SuccessMessage = $"Product '{NewProduct.Name}' has been created successfully.";
                return RedirectToPage();
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error creating product: {ex.Message}";
                Products = (await _productService.GetAllProductsAsync()).ToList();
                return Page();
            }
        }

        public async Task<IActionResult> OnPostEditAsync(int id, string name, string description, decimal price, 
            int stockQuantity, bool isAvailable, IFormFile uploadedImage, string imageDescription)
        {
            // Sanitize inputs
            name = SqlInputSanitizer.SanitizeString(name);
            description = SqlInputSanitizer.SanitizeString(description);
            imageDescription = SqlInputSanitizer.SanitizeString(imageDescription);
            
            var product = await _productService.GetProductByIdAsync(id);
            if (product == null)
            {
                ErrorMessage = "Product not found.";
                return RedirectToPage();
            }

            try
            {
                // Update basic info
                product.Name = name;
                product.Description = description;
                product.Price = price;
                product.StockQuantity = stockQuantity;
                product.IsAvailable = isAvailable;
                product.ImageDescription = imageDescription ?? product.ImageDescription;
                
                // Handle file upload if provided
                if (uploadedImage != null && uploadedImage.Length > 0)
                {
                    string uploadsFolder = Path.Combine(_webHostEnvironment.WebRootPath, "uploads", "products");
                    
                    // Ensure directory exists
                    if (!Directory.Exists(uploadsFolder))
                    {
                        Directory.CreateDirectory(uploadsFolder);
                    }
                    
                    // Create unique filename
                    string uniqueFileName = Guid.NewGuid().ToString() + "_" + SqlInputSanitizer.SanitizeString(uploadedImage.FileName);
                    string filePath = Path.Combine(uploadsFolder, uniqueFileName);
                    
                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        await uploadedImage.CopyToAsync(fileStream);
                    }
                    
                    // Update product image URL
                    product.ImageUrl = "/uploads/products/" + uniqueFileName;
                }

                await _productService.UpdateProductAsync(product);
                SuccessMessage = $"Product '{product.Name}' has been updated successfully.";
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error updating product: {ex.Message}";
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostToggleAvailabilityAsync(int id)
        {
            var product = await _productService.GetProductByIdAsync(id);
            if (product == null)
            {
                ErrorMessage = "Product not found.";
                return RedirectToPage();
            }

            try
            {
                await _productService.UpdateProductAvailabilityAsync(id, !product.IsAvailable);
                
                SuccessMessage = $"Product '{product.Name}' is now {(product.IsAvailable ? "unavailable" : "available")}.";
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error updating product availability: {ex.Message}";
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDeleteAsync(int id)
        {
            var product = await _productService.GetProductByIdAsync(id);
            if (product == null)
            {
                ErrorMessage = "Product not found.";
                return RedirectToPage();
            }

            try
            {
                await _productService.DeleteProductAsync(id);
                SuccessMessage = $"Product '{product.Name}' has been deleted successfully.";
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error deleting product: {ex.Message}";
            }

            return RedirectToPage();
        }
    }
} 