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
                .ToListAsync();
        }

        public async Task<PageTemplate> GetTemplateByIdAsync(int id)
        {
            return await _context.PageTemplates
                .Include(t => t.Elements)
                .FirstOrDefaultAsync(t => t.Id == id);
        }

        public async Task<PageTemplate> GetTemplateByNameAsync(string name)
        {
            return await _context.PageTemplates
                .Include(t => t.Elements)
                .ThenInclude(e => e.Images)
                .FirstOrDefaultAsync(t => t.Name == name);
        }

        public async Task<PageTemplate> GetActiveTemplateAsync()
        {
            return await _context.PageTemplates
                .Include(t => t.Elements)
                .ThenInclude(e => e.Images)
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
            _context.Entry(template).State = EntityState.Modified;
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