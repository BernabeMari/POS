using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;

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
                .ToListAsync();
        }

        public async Task<PageElement> GetElementByIdAsync(int id)
        {
            return await _context.PageElements.FindAsync(id);
        }

        public async Task<PageElement> CreateElementAsync(PageElement element)
        {
            element.LastModified = DateTime.Now;
            _context.PageElements.Add(element);
            await _context.SaveChangesAsync();
            return element;
        }

        public async Task<PageElement> UpdateElementAsync(PageElement element)
        {
            element.LastModified = DateTime.Now;
            _context.Entry(element).State = EntityState.Modified;
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
                .FirstOrDefaultAsync(t => t.Id == templateId);
                
            return template?.Elements ?? Enumerable.Empty<PageElement>();
        }
    }
} 