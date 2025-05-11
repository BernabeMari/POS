using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using POS.Services;

namespace POS.Services
{
    public class PageElementService : IPageElementService
    {
        private readonly ApplicationDbContext _context;

        public PageElementService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<PageElement>> GetElementsByPageNameAsync(string pageName)
        {
            return await _context.PageElements
                .Where(e => e.PageName == pageName)
                .Include(e => e.Images)
                .Include(e => e.Ingredients)
                .ToListAsync();
        }

        public async Task<IEnumerable<PageElement>> GetAvailableElementsByPageNameAsync(string pageName)
        {
            return await _context.PageElements
                .Where(e => e.PageName == pageName && e.IsProduct && e.IsAvailable)
                .Include(e => e.Images)
                .Include(e => e.Ingredients)
                .ToListAsync();
        }

        public async Task<PageElement> GetElementByIdAsync(int id)
        {
            return await _context.PageElements
                .Include(e => e.Images)
                .Include(e => e.Ingredients)
                .FirstOrDefaultAsync(e => e.Id == id);
        }

        public async Task<PageElement> CreateElementAsync(PageElement element)
        {
            element.LastModified = DateTime.Now;
            
            // Sanitize product data
            if (element.IsProduct)
            {
                element.ProductName = SqlInputSanitizer.SanitizeString(element.ProductName);
                element.ProductDescription = SqlInputSanitizer.SanitizeString(element.ProductDescription);
                
                // Sanitize ingredients if any
                if (element.Ingredients != null)
                {
                    foreach (var ingredient in element.Ingredients)
                    {
                        ingredient.IngredientName = SqlInputSanitizer.SanitizeString(ingredient.IngredientName);
                        ingredient.Unit = SqlInputSanitizer.SanitizeString(ingredient.Unit);
                        ingredient.Notes = SqlInputSanitizer.SanitizeString(ingredient.Notes);
                    }
                }
            }
            
            _context.PageElements.Add(element);
            await _context.SaveChangesAsync();
            return element;
        }

        public async Task<PageElement> UpdateElementAsync(PageElement element)
        {
            element.LastModified = DateTime.Now;
            
            // Sanitize product data
            if (element.IsProduct)
            {
                element.ProductName = SqlInputSanitizer.SanitizeString(element.ProductName);
                element.ProductDescription = SqlInputSanitizer.SanitizeString(element.ProductDescription);
                
                // Sanitize ingredients if any
                if (element.Ingredients != null)
                {
                    foreach (var ingredient in element.Ingredients)
                    {
                        ingredient.IngredientName = SqlInputSanitizer.SanitizeString(ingredient.IngredientName);
                        ingredient.Unit = SqlInputSanitizer.SanitizeString(ingredient.Unit);
                        ingredient.Notes = SqlInputSanitizer.SanitizeString(ingredient.Notes);
                    }
                }
            }
            
            // When updating an element with collections, we need special handling
            // Detach any existing entity with the same ID to avoid conflicts
            var existingElement = await _context.PageElements
                .Include(e => e.Images)
                .Include(e => e.Ingredients)
                .FirstOrDefaultAsync(e => e.Id == element.Id);
            
            if (existingElement != null)
            {
                // Set entity state to modified
                _context.Entry(existingElement).State = EntityState.Detached;
            }
            
            // Now attach and mark the updated entity as modified
            _context.Entry(element).State = EntityState.Modified;
            
            // Handle the collections
            foreach (var image in element.Images)
            {
                if (image.Id == 0)
                {
                    // New image
                    _context.Entry(image).State = EntityState.Added;
                }
                else
                {
                    // Existing image
                    _context.Entry(image).State = EntityState.Modified;
                }
            }
            
            foreach (var ingredient in element.Ingredients)
            {
                if (ingredient.Id == 0)
                {
                    // New ingredient
                    _context.Entry(ingredient).State = EntityState.Added;
                }
                else
                {
                    // Existing ingredient
                    _context.Entry(ingredient).State = EntityState.Modified;
                }
            }
            
            // Save changes to the database
            await _context.SaveChangesAsync();
            
            return element;
        }

        public async Task DeleteElementAsync(int id)
        {
            var element = await _context.PageElements.FindAsync(id);
            if (element != null)
            {
                _context.PageElements.Remove(element);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<IEnumerable<PageElement>> GetElementsByTemplateIdAsync(int templateId)
        {
            var template = await _context.PageTemplates
                .Include(t => t.Elements)
                .ThenInclude(e => e.Images)
                .Include(t => t.Elements)
                .ThenInclude(e => e.Ingredients)
                .FirstOrDefaultAsync(t => t.Id == templateId);
                
            return template?.Elements ?? Enumerable.Empty<PageElement>();
        }
    }
} 