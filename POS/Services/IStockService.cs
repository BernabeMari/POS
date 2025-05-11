using POS.Models;

namespace POS.Services
{
    public interface IStockService
    {
        Task<Stock> GetStockByNameAsync(string ingredientName);
        Task<IEnumerable<Stock>> GetAllStocksAsync();
        Task<IEnumerable<Stock>> GetLowStockItemsAsync();
        Task<Stock> AddStockAsync(Stock stock);
        Task<Stock> UpdateStockAsync(Stock stock);
        Task<bool> DeleteStockAsync(int stockId);
        Task<bool> DeductIngredientStockAsync(string ingredientName, decimal quantity, string unitType, string reason = "Order");
        Task<bool> UpdateStockForOrderAsync(PageElement productElement, int quantity, string userId);
        Task<StockHistory> AddStockHistoryAsync(StockHistory stockHistory);
    }
} 