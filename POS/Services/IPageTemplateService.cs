using POS.Models;

namespace POS.Services
{
    public interface IPageTemplateService
    {
        Task<IEnumerable<PageTemplate>> GetAllTemplatesAsync();
        Task<PageTemplate> GetTemplateByIdAsync(int id);
        Task<PageTemplate> GetTemplateByNameAsync(string name);
        Task<PageTemplate> GetActiveTemplateAsync();
        Task<PageTemplate> CreateTemplateAsync(PageTemplate template);
        Task<PageTemplate> UpdateTemplateAsync(PageTemplate template);
        Task DeleteTemplateAsync(int id);
        Task SetActiveTemplateAsync(int id);
    }
} 