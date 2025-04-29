using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using POS.Data;
using POS.Models;

namespace POS.Services
{
    public class CartService : ICartService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<CartService> _logger;

        public CartService(ApplicationDbContext context, ILogger<CartService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<CartItem>> GetCartItemsByUserIdAsync(string userId)
        {
            return await _context.CartItems
                .Where(c => c.UserId == userId)
                .OrderByDescending(c => c.CreatedAt)
                .ToListAsync();
        }

        public async Task<CartItem> GetCartItemByIdAsync(int id)
        {
            return await _context.CartItems.FindAsync(id);
        }

        public async Task<CartItem> AddToCartAsync(CartItem cartItem)
        {
            try
            {
                _logger.LogInformation($"Adding cart item for user {cartItem.UserId}");
                
                // Check if the user exists
                var userExists = await _context.Users.AnyAsync(u => u.Id == cartItem.UserId);
                if (!userExists)
                {
                    _logger.LogError($"User with ID {cartItem.UserId} does not exist");
                    throw new InvalidOperationException($"User with ID {cartItem.UserId} does not exist");
                }
                
                // Check if the product already exists in the cart
                // First check by ProductId if it exists
                var existingItem = cartItem.ProductId.HasValue
                    ? await _context.CartItems.FirstOrDefaultAsync(
                        c => c.UserId == cartItem.UserId && c.ProductId == cartItem.ProductId)
                    : await _context.CartItems.FirstOrDefaultAsync(
                        c => c.UserId == cartItem.UserId && 
                        c.ProductName == cartItem.ProductName && 
                        c.Price == cartItem.Price);
                
                if (existingItem != null)
                {
                    _logger.LogInformation($"Updating existing cart item {existingItem.Id}");
                    // Update quantity instead of adding a new item
                    existingItem.Quantity += cartItem.Quantity;
                    existingItem.UpdatedAt = DateTime.Now;
                    
                    try
                    {
                        await _context.SaveChangesAsync();
                        return existingItem;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error updating existing cart item");
                        throw;
                    }
                }
                
                // Add new item
                cartItem.CreatedAt = DateTime.Now;
                
                // Ensure ProductImageDescription is not null
                if (string.IsNullOrEmpty(cartItem.ProductImageDescription))
                {
                    cartItem.ProductImageDescription = cartItem.ProductName;
                }
                
                // Ensure proper decimal precision for Price
                cartItem.Price = Math.Round(cartItem.Price, 2);
                
                _logger.LogInformation($"Adding new cart item: {System.Text.Json.JsonSerializer.Serialize(cartItem)}");
                
                _context.CartItems.Add(cartItem);
                
                try
                {
                    await _context.SaveChangesAsync();
                    return cartItem;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error saving new cart item");
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in AddToCartAsync");
                throw;
            }
        }

        public async Task<CartItem> UpdateCartItemAsync(CartItem cartItem)
        {
            cartItem.UpdatedAt = DateTime.Now;
            _context.Entry(cartItem).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return cartItem;
        }

        public async Task<bool> RemoveFromCartAsync(int cartItemId)
        {
            var cartItem = await _context.CartItems.FindAsync(cartItemId);
            if (cartItem == null)
                return false;

            _context.CartItems.Remove(cartItem);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ClearCartAsync(string userId)
        {
            var cartItems = await _context.CartItems
                .Where(c => c.UserId == userId)
                .ToListAsync();
                
            if (!cartItems.Any())
                return false;
                
            _context.CartItems.RemoveRange(cartItems);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<int> GetCartItemCountAsync(string userId)
        {
            return await _context.CartItems
                .Where(c => c.UserId == userId)
                .SumAsync(c => c.Quantity);
        }

        public async Task<decimal> GetCartTotalAsync(string userId)
        {
            _logger.LogInformation($"Calculating cart total for user: {userId}");
            var cartItems = await _context.CartItems
                .Where(c => c.UserId == userId)
                .ToListAsync();
                
            _logger.LogInformation($"Found {cartItems.Count} cart items for total calculation");
            
            foreach (var item in cartItems)
            {
                _logger.LogInformation($"Cart item: ID={item.Id}, Product={item.ProductName}, Price={item.Price}, Quantity={item.Quantity}, Total={item.Price * item.Quantity}");
            }
            
            decimal total = cartItems.Sum(c => c.Price * c.Quantity);
            _logger.LogInformation($"Final cart total: {total}");
            
            return total;
        }
    }
} 