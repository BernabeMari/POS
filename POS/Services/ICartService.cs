using POS.Models;

namespace POS.Services
{
    public interface ICartService
    {
        Task<IEnumerable<CartItem>> GetCartItemsByUserIdAsync(string userId);
        Task<CartItem> GetCartItemByIdAsync(int id);
        Task<CartItem> AddToCartAsync(CartItem cartItem);
        Task<CartItem> UpdateCartItemAsync(CartItem cartItem);
        Task<bool> RemoveFromCartAsync(int cartItemId);
        Task<bool> ClearCartAsync(string userId);
        Task<int> GetCartItemCountAsync(string userId);
        Task<decimal> GetCartTotalAsync(string userId);
    }
} 