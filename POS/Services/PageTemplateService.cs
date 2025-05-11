using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;

namespace POS.Services
{
    public class PageTemplateService : IPageTemplateService
    {
        private readonly ApplicationDbContext _context;

        public PageTemplateService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<PageTemplate>> GetAllTemplatesAsync()
        {
            return await _context.PageTemplates
                .Include(t => t.Elements)
                .ThenInclude(e => e.Images)
                .Include(t => t.Elements)
                .ThenInclude(e => e.Ingredients)
                .ToListAsync();
        }

        public async Task<PageTemplate> GetTemplateByIdAsync(int id)
        {
            return await _context.PageTemplates
                .Include(t => t.Elements)
                .ThenInclude(e => e.Images)
                .Include(t => t.Elements)
                .ThenInclude(e => e.Ingredients)
                .FirstOrDefaultAsync(t => t.Id == id);
        }

        public async Task<PageTemplate> GetTemplateByNameAsync(string name)
        {
            return await _context.PageTemplates
                .Include(t => t.Elements)
                .ThenInclude(e => e.Images)
                .Include(t => t.Elements)
                .ThenInclude(e => e.Ingredients)
                .FirstOrDefaultAsync(t => t.Name == name);
        }

        public async Task<PageTemplate> GetActiveTemplateAsync()
        {
            return await _context.PageTemplates
                .Include(t => t.Elements)
                .ThenInclude(e => e.Images)
                .Include(t => t.Elements)
                .ThenInclude(e => e.Ingredients)
                .FirstOrDefaultAsync(t => t.IsActive);
        }

        public async Task<PageTemplate> CreateTemplateAsync(PageTemplate template)
        {
            _context.PageTemplates.Add(template);
            await _context.SaveChangesAsync();
            return template;
        }

        public async Task<PageTemplate> UpdateTemplateAsync(PageTemplate template)
        {
            template.LastModified = DateTime.Now;
            
            // To properly handle collections like Ingredients, we need to use a different approach
            // First, mark the template as modified
            _context.Entry(template).State = EntityState.Modified;
            
            // For each element, ensure its state is properly tracked
            foreach (var element in template.Elements)
            {
                if (element.Id > 0)
                {
                    // Existing element - update it
                    _context.Entry(element).State = EntityState.Modified;
                }
                else
                {
                    // New element - add it
                    _context.Entry(element).State = EntityState.Added;
                }
                
                // Handle Images collection
                foreach (var image in element.Images)
                {
                    if (image.Id > 0)
                    {
                        _context.Entry(image).State = EntityState.Modified;
                    }
                    else
                    {
                        _context.Entry(image).State = EntityState.Added;
                    }
                }
                
                // Handle Ingredients collection
                foreach (var ingredient in element.Ingredients)
                {
                    if (ingredient.Id > 0)
                    {
                        _context.Entry(ingredient).State = EntityState.Modified;
                    }
                    else
                    {
                        _context.Entry(ingredient).State = EntityState.Added;
                    }
                }
            }
            
            await _context.SaveChangesAsync();
            return template;
        }

        public async Task DeleteTemplateAsync(int id)
        {
            var template = await _context.PageTemplates.FindAsync(id);
            if (template != null)
            {
                _context.PageTemplates.Remove(template);
                await _context.SaveChangesAsync();
            }
        }

        public async Task SetActiveTemplateAsync(int id)
        {
            // First, deactivate all templates
            var templates = await _context.PageTemplates.ToListAsync();
            foreach (var template in templates)
            {
                template.IsActive = false;
            }

            // Then, activate the requested template
            var activeTemplate = await _context.PageTemplates.FindAsync(id);
            if (activeTemplate != null)
            {
                activeTemplate.IsActive = true;
                activeTemplate.LastModified = DateTime.Now;
            }

            await _context.SaveChangesAsync();
        }
    }
} 