using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using POS.Services;

namespace POS.Services
{
    public class ProductService : IProductService
    {
        private readonly ApplicationDbContext _context;

        public ProductService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<Product>> GetAllProductsAsync()
        {
            return await _context.Products
                .OrderByDescending(p => p.CreatedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<Product>> GetAvailableProductsAsync()
        {
            return await _context.Products
                .Where(p => p.IsAvailable && p.StockQuantity > 0)
                .OrderByDescending(p => p.CreatedAt)
                .ToListAsync();
        }

        public async Task<Product> GetProductByIdAsync(int id)
        {
            return await _context.Products.FindAsync(id);
        }

        public async Task<Product> CreateProductAsync(Product product)
        {
            // Sanitize product inputs
            SanitizeProduct(product);
            
            product.CreatedAt = DateTime.Now;
            _context.Products.Add(product);
            await _context.SaveChangesAsync();
            return product;
        }

        public async Task<Product> UpdateProductAsync(Product product)
        {
            // Sanitize product inputs
            SanitizeProduct(product);
            
            product.UpdatedAt = DateTime.Now;
            _context.Entry(product).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return product;
        }

        public async Task<bool> DeleteProductAsync(int id)
        {
            var product = await _context.Products.FindAsync(id);
            if (product == null)
                return false;

            _context.Products.Remove(product);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<Product> UpdateProductAvailabilityAsync(int productId, bool isAvailable)
        {
            var product = await _context.Products.FindAsync(productId);
            if (product == null)
                return null;

            product.IsAvailable = isAvailable;
            product.UpdatedAt = DateTime.Now;
            
            await _context.SaveChangesAsync();
            return product;
        }
        
        // Helper method to sanitize product data
        private void SanitizeProduct(Product product)
        {
            if (product == null) return;
            
            product.Name = SqlInputSanitizer.SanitizeString(product.Name);
            product.Description = SqlInputSanitizer.SanitizeString(product.Description);
            product.ImageUrl = SqlInputSanitizer.SanitizeString(product.ImageUrl);
            product.ImageDescription = SqlInputSanitizer.SanitizeString(product.ImageDescription);
        }
    }
} 