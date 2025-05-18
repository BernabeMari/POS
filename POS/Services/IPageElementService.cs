using POS.Models;

namespace POS.Services
{
    public interface IPageElementService
    {
        Task<IEnumerable<PageElement>> GetElementsByPageNameAsync(string pageName);
        Task<IEnumerable<PageElement>> GetAvailableElementsByPageNameAsync(string pageName);
        Task<PageElement> GetElementByIdAsync(int id);
        Task<PageElement> CreateElementAsync(PageElement element);
        Task<PageElement> UpdateElementAsync(PageElement element);
        Task DeleteElementAsync(int id);
        Task<IEnumerable<PageElement>> GetElementsByTemplateIdAsync(int templateId);
    }
} 