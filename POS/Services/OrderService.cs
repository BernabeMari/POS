using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using POS.Data;
using POS.Models;

namespace POS.Services
{
    public class OrderService : IOrderService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<OrderService> _logger;
        private readonly IStockService _stockService;

        public OrderService(ApplicationDbContext context, ILogger<OrderService> logger, IStockService stockService)
        {
            _context = context;
            _logger = logger;
            _stockService = stockService;
        }

        public async Task<IEnumerable<Order>> GetAllOrdersAsync()
        {
            return await _context.Orders
                .Include(o => o.User)
                .Include(o => o.AssignedEmployee)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<Order>> GetOrdersByUserIdAsync(string userId)
        {
            return await _context.Orders
                .Include(o => o.AssignedEmployee)
                .Where(o => o.UserId == userId)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<Order>> GetOrdersByEmployeeIdAsync(string employeeId)
        {
            return await _context.Orders
                .Include(o => o.User)
                .Where(o => o.AssignedToEmployeeId == employeeId)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }

        public async Task<IEnumerable<Order>> GetPendingOrdersAsync()
        {
            return await _context.Orders
                .Include(o => o.User)
                .Where(o => o.Status == OrderStatus.Pending)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }

        public async Task<Order> GetOrderByIdAsync(int id)
        {
            return await _context.Orders
                .Include(o => o.User)
                .Include(o => o.AssignedEmployee)
                .FirstOrDefaultAsync(o => o.Id == id);
        }

        public async Task<Order> CreateOrderAsync(Order order)
        {
            // Calculate total price if not set
            if (order.TotalPrice == 0)
            {
                order.TotalPrice = order.Price * order.Quantity;
            }
            
            order.CreatedAt = DateTime.Now;
            _context.Orders.Add(order);
            await _context.SaveChangesAsync();
            return order;
        }

        public async Task<Order> UpdateOrderAsync(Order order)
        {
            order.UpdatedAt = DateTime.Now;
            _context.Entry(order).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return order;
        }

        public async Task<bool> DeleteOrderAsync(int id)
        {
            var order = await _context.Orders.FindAsync(id);
            if (order == null)
                return false;

            _context.Orders.Remove(order);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<Order> AssignOrderToEmployeeAsync(int orderId, string employeeId)
        {
            var order = await _context.Orders.FindAsync(orderId);
            if (order == null)
                return null;
                
            order.AssignedToEmployeeId = employeeId;
            order.Status = OrderStatus.OrderReceived;
            order.UpdatedAt = DateTime.Now;
            
            await _context.SaveChangesAsync();
            return order;
        }

        public async Task<Order> UpdateOrderStatusAsync(int orderId, OrderStatus status)
        {
            var order = await _context.Orders.FindAsync(orderId);
            if (order == null)
                return null;

            order.Status = status;
            order.UpdatedAt = DateTime.Now;
            
            await _context.SaveChangesAsync();
            return order;
        }
        
        public async Task<IEnumerable<Order>> GetNewOrdersAsync()
        {
            _logger.LogInformation("Fetching new orders...");
            
            try
            {
                // Get all pending orders that aren't assigned to anyone
                var orders = await _context.Orders
                    .Include(o => o.User)
                    .Where(o => o.Status == OrderStatus.Pending && o.AssignedToEmployeeId == null)
                    .OrderByDescending(o => o.CreatedAt)
                    .ToListAsync();
                
                _logger.LogInformation($"Found {orders.Count} new orders");
                
                return orders;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching new orders");
                return Enumerable.Empty<Order>();
            }
        }
        
        public async Task<IEnumerable<Order>> GetAssignedOrdersAsync(string employeeId)
        {
            return await _context.Orders
                .Include(o => o.User)
                .Where(o => o.AssignedToEmployeeId == employeeId && 
                          (o.Status == OrderStatus.Processing || 
                           o.Status == OrderStatus.OrderReceived || 
                           o.Status == OrderStatus.OnGoing))
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }
        
        public async Task<IEnumerable<Order>> GetOrderHistoryAsync(string employeeId = null)
        {
            var query = _context.Orders
                .Include(o => o.User)
                .Include(o => o.AssignedEmployee)
                .Where(o => o.Status == OrderStatus.Completed || 
                          o.Status == OrderStatus.Complete || 
                          o.Status == OrderStatus.Cancelled);
                
            if (!string.IsNullOrEmpty(employeeId))
            {
                query = query.Where(o => o.AssignedToEmployeeId == employeeId);
            }
            
            return await query
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }
        
        public async Task<Order> CompleteOrderAsync(int orderId)
        {
            var order = await _context.Orders
                .Include(o => o.User)  // Include user for reference
                .FirstOrDefaultAsync(o => o.Id == orderId);
                
            if (order == null)
                return null;
            
            // Begin transaction to ensure both order status update and stock deduction succeed or fail together
            using var transaction = await _context.Database.BeginTransactionAsync();
            
            try
            {
                // Update order status - always use OrderStatus.Completed for consistency
                order.Status = OrderStatus.Completed;
                order.UpdatedAt = DateTime.Now;
                await _context.SaveChangesAsync();
                
                // Deduct stock for ingredients based on the product in this order
                await DeductStockForCompletedOrderAsync(order);
                
                // Commit the transaction
                await transaction.CommitAsync();
                _logger.LogInformation($"Order {orderId} marked as completed and stock updated");
                
                return order;
            }
            catch (Exception ex)
            {
                // If anything goes wrong, roll back the transaction
                await transaction.RollbackAsync();
                _logger.LogError(ex, $"Error completing order and updating stock: {ex.Message}");
                throw;
            }
        }

        // New method to handle stock deduction for completed orders
        private async Task DeductStockForCompletedOrderAsync(Order order)
        {
            _logger.LogInformation($"[STOCK-DEBUG] Processing stock deduction for order {order.Id}, product '{order.ProductName}'");
            
            // DIAGNOSTIC: Log all products in the database first
            var allProductsInDb = await _context.PageElements
                .Where(p => p.IsProduct)
                .Select(p => new { p.Id, p.ProductName })
                .ToListAsync();
                
            _logger.LogInformation($"[STOCK-DEBUG] All products in database: {string.Join(", ", allProductsInDb.Select(p => $"{p.ProductName} (ID: {p.Id})"))}");
            
            // DIAGNOSTIC: Log all ingredients in the database
            var allIngredientsInDb = await _context.ProductIngredients
                .Select(i => new { i.Id, i.PageElementId, i.IngredientName })
                .ToListAsync();
                
            _logger.LogInformation($"[STOCK-DEBUG] All ingredients in database: {string.Join(", ", allIngredientsInDb.Select(i => $"{i.IngredientName} (ID: {i.Id}, ProductID: {i.PageElementId})"))}");
            
            // First, try to directly query the ingredients based on the product name from the order
            _logger.LogInformation($"[STOCK-DEBUG] Searching for product with name '{order.ProductName}'");
            
            var productMatches = await _context.PageElements
                .Where(p => p.IsProduct && 
                    (p.ProductName.ToLower() == order.ProductName.ToLower() || 
                     p.ProductName.ToLower().Contains(order.ProductName.ToLower()) || 
                     order.ProductName.ToLower().Contains(p.ProductName.ToLower())))
                .Select(p => new { p.Id, p.ProductName })
                .ToListAsync();
                
            _logger.LogInformation($"[STOCK-DEBUG] Found {productMatches.Count} potential product matches: {string.Join(", ", productMatches.Select(p => $"{p.ProductName} (ID: {p.Id})"))}");
            
            if (!productMatches.Any())
            {
                _logger.LogError($"[STOCK-DEBUG] No product matches found for order {order.Id} with product name '{order.ProductName}'");
                return;
            }
            
            // See which of the potential matches has ingredients
            int bestProductId = -1;
            string bestProductName = null;
            
            foreach (var match in productMatches)
            {
                var ingredients = await _context.ProductIngredients
                    .Where(i => i.PageElementId == match.Id)
                    .ToListAsync();
                    
                _logger.LogInformation($"[STOCK-DEBUG] Product {match.ProductName} (ID: {match.Id}) has {ingredients.Count} ingredients");
                
                if (ingredients.Any())
                {
                    bestProductId = match.Id;
                    bestProductName = match.ProductName;
                    break;
                }
            }
            
            if (bestProductId == -1)
            {
                _logger.LogError($"[STOCK-DEBUG] None of the potential product matches has ingredients");
                return;
            }
            
            _logger.LogInformation($"[STOCK-DEBUG] Selected product {bestProductName} (ID: {bestProductId}) as the best match");
            
            // Load the selected product with its ingredients
            var productElement = await _context.PageElements
                .Include(e => e.Ingredients)
                .FirstOrDefaultAsync(e => e.Id == bestProductId);
                
            if (productElement == null)
            {
                _logger.LogError($"[STOCK-DEBUG] Failed to load selected product with ID {bestProductId}");
                return;
            }
            
            // Double check if ingredients are loaded
            if (productElement.Ingredients == null || !productElement.Ingredients.Any())
            {
                _logger.LogInformation($"[STOCK-DEBUG] Product loaded but ingredients not included, trying direct query");
                
                // Try directly querying for ingredients
                var ingredients = await _context.ProductIngredients
                    .Where(i => i.PageElementId == productElement.Id)
                    .ToListAsync();
                    
                if (ingredients.Any())
                {
                    _logger.LogInformation($"[STOCK-DEBUG] Found {ingredients.Count} ingredients via direct query");
                    productElement.Ingredients = ingredients;
                }
                else
                {
                    _logger.LogError($"[STOCK-DEBUG] No ingredients found for product {productElement.ProductName} (ID: {productElement.Id})");
                    return;
                }
            }
            
            // Log all ingredients for this product
            _logger.LogInformation($"[STOCK-DEBUG] Product {productElement.ProductName} has {productElement.Ingredients.Count} ingredients:");
            foreach (var ingredient in productElement.Ingredients)
            {
                _logger.LogInformation($"[STOCK-DEBUG] - Ingredient: {ingredient.IngredientName}, Quantity: {ingredient.Quantity}, Unit: {ingredient.Unit}");
            }
            
            // DIAGNOSTIC: Check stock status for each ingredient before deduction
            foreach (var ingredient in productElement.Ingredients)
            {
                var stock = await _stockService.GetStockByNameAsync(ingredient.IngredientName);
                if (stock != null)
                {
                    _logger.LogInformation($"[STOCK-DEBUG] Ingredient {ingredient.IngredientName} has {stock.Quantity} {stock.UnitType} in stock");
                }
                else
                {
                    _logger.LogWarning($"[STOCK-DEBUG] Ingredient {ingredient.IngredientName} not found in stock");
                }
            }
            
            // Update stock for all ingredients
            bool stockUpdated = await _stockService.UpdateStockForOrderAsync(
                productElement, 
                order.Quantity, 
                order.UserId
            );
            
            if (!stockUpdated)
            {
                _logger.LogWarning($"[STOCK-DEBUG] Failed to update stock for some ingredients in completed order {order.Id}");
                
                // DIAGNOSTIC: Check stock status for each ingredient after attempted deduction
                foreach (var ingredient in productElement.Ingredients)
                {
                    var stock = await _stockService.GetStockByNameAsync(ingredient.IngredientName);
                    if (stock != null)
                    {
                        _logger.LogInformation($"[STOCK-DEBUG] After attempt: Ingredient {ingredient.IngredientName} has {stock.Quantity} {stock.UnitType} in stock");
                    }
                    else
                    {
                        _logger.LogWarning($"[STOCK-DEBUG] After attempt: Ingredient {ingredient.IngredientName} not found in stock");
                    }
                }
            }
            else
            {
                _logger.LogInformation($"[STOCK-DEBUG] Successfully deducted stock for all ingredients in order {order.Id}");
                
                // DIAGNOSTIC: Verify stock was actually updated
                foreach (var ingredient in productElement.Ingredients)
                {
                    var stock = await _stockService.GetStockByNameAsync(ingredient.IngredientName);
                    if (stock != null)
                    {
                        _logger.LogInformation($"[STOCK-DEBUG] After successful deduction: Ingredient {ingredient.IngredientName} has {stock.Quantity} {stock.UnitType} in stock");
                    }
                    else
                    {
                        _logger.LogWarning($"[STOCK-DEBUG] After successful deduction: Ingredient {ingredient.IngredientName} not found in stock");
                    }
                }
            }
        }

        public async Task<IEnumerable<Order>> GetLatestOrdersAsync(int sinceId = 0)
        {
            return await _context.Orders
                .Include(o => o.User)
                .Where(o => o.Id > sinceId && o.Status == OrderStatus.Pending)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }
        
        // Discount management methods
        public async Task<Order> RequestDiscountAsync(int orderId, string discountType)
        {
            _logger.LogInformation($"Requesting {discountType} discount for order ID: {orderId}");
            
            var order = await _context.Orders
                .Include(o => o.User)
                .FirstOrDefaultAsync(o => o.Id == orderId);
                
            if (order == null)
            {
                _logger.LogWarning($"Order not found: {orderId}");
                return null;
            }
            
            // Mark only the current order as awaiting discount approval instead of all pending orders
            // This ensures a single request for the entire cart
            order.IsDiscountRequested = true;
            order.DiscountType = discountType;
            order.Status = OrderStatus.AwaitingDiscountApproval;
            order.OriginalTotalPrice = order.TotalPrice;
            order.UpdatedAt = DateTime.Now;
            
            await _context.SaveChangesAsync();
            
            return order;
        }
        
        public async Task<Order> ApproveDiscountAsync(int orderId, string managerId, decimal discountPercentage = 20)
        {
            _logger.LogInformation($"Approving discount for order ID: {orderId} by manager ID: {managerId}");
            
            var order = await _context.Orders
                .Include(o => o.User)
                .FirstOrDefaultAsync(o => o.Id == orderId);
                
            if (order == null)
            {
                _logger.LogWarning($"Order not found: {orderId}");
                return null;
            }
            
            if (!order.IsDiscountRequested)
            {
                _logger.LogWarning($"No discount was requested for order: {orderId}");
                return order;
            }
            
            // Apply discount to just this order instead of all pending orders
            order.IsDiscountApproved = true;
            order.DiscountApprovedById = managerId;
            order.DiscountPercentage = discountPercentage;
            
            // Store original price if not already stored
            if (order.OriginalTotalPrice <= 0)
            {
                order.OriginalTotalPrice = order.TotalPrice;
            }
            
            // Calculate discount amount
            order.DiscountAmount = Math.Round(order.OriginalTotalPrice * (discountPercentage / 100), 2);
            
            // Update total price with discount
            order.TotalPrice = order.OriginalTotalPrice - order.DiscountAmount;
            
            // Set the order status back to Pending so payment can proceed
            order.Status = OrderStatus.Pending;
            order.UpdatedAt = DateTime.Now;
            
            await _context.SaveChangesAsync();
            
            return order;
        }
        
        public async Task<Order> DenyDiscountAsync(int orderId, string managerId)
        {
            _logger.LogInformation($"Denying discount for order ID: {orderId} by manager ID: {managerId}");
            
            var order = await _context.Orders
                .FirstOrDefaultAsync(o => o.Id == orderId);
                
            if (order == null)
            {
                _logger.LogWarning($"Order not found: {orderId}");
                return null;
            }
            
            // Reset discount properties for just this order
            order.IsDiscountRequested = false;
            order.IsDiscountApproved = false;
            order.DiscountType = null;
            order.DiscountAmount = 0;
            order.DiscountPercentage = 0;
            
            // Ensure price is back to original
            if (order.OriginalTotalPrice > 0)
            {
                order.TotalPrice = order.OriginalTotalPrice;
                order.OriginalTotalPrice = 0;
            }
            
            // Reset status to Pending
            order.Status = OrderStatus.Pending;
            order.UpdatedAt = DateTime.Now;
            
            await _context.SaveChangesAsync();
            
            return order;
        }
        
        public async Task<Order> SkipDiscountAsync(int orderId)
        {
            _logger.LogInformation($"Skipping discount for order ID: {orderId}");
            
            var order = await _context.Orders
                .FirstOrDefaultAsync(o => o.Id == orderId);
                
            if (order == null)
            {
                _logger.LogWarning($"Order not found: {orderId}");
                return null;
            }
            
            // Set discount properties for just this order to indicate it was explicitly skipped
            order.IsDiscountRequested = false;
            order.IsDiscountApproved = false;
            order.DiscountType = "Skipped";
            order.DiscountAmount = 0;
            order.DiscountPercentage = 0;
            
            // Ensure price is back to original
            if (order.OriginalTotalPrice > 0)
            {
                order.TotalPrice = order.OriginalTotalPrice;
                order.OriginalTotalPrice = 0;
            }
            
            await _context.SaveChangesAsync();
            
            return order;
        }
        
        public async Task<IEnumerable<Order>> GetOrdersAwaitingDiscountApprovalAsync()
        {
            return await _context.Orders
                .Include(o => o.User)
                .Where(o => o.Status == OrderStatus.AwaitingDiscountApproval)
                .OrderByDescending(o => o.CreatedAt)
                .ToListAsync();
        }

        public async Task<Order> CreateOrderAndUpdateStockAsync(Order order, PageElement productElement)
        {
            _logger.LogInformation($"Creating order for product: {productElement.ProductName}");
            
            // Make sure we have a fully loaded element with all its ingredients for validation
            if (productElement.Ingredients == null || !productElement.Ingredients.Any())
            {
                _logger.LogWarning($"Product element didn't have ingredients loaded. Reloading from database.");
                
                // Reload the product element with its ingredients
                var reloadedElement = await _context.PageElements
                    .Include(e => e.Ingredients)
                    .FirstOrDefaultAsync(e => e.Id == productElement.Id);
                    
                if (reloadedElement != null)
                {
                    productElement = reloadedElement;
                    _logger.LogInformation($"Successfully reloaded product element. Found {productElement.Ingredients?.Count ?? 0} ingredients.");
                }
            }
            
            // Check if product element has ingredients after reloading
            if (productElement.Ingredients == null || !productElement.Ingredients.Any())
            {
                _logger.LogWarning($"Product {productElement.ProductName} does not have any ingredients configured. Creating order without ingredient validation.");
                
                // Just create the order without stock validation since there are no ingredients to validate
                return await CreateOrderAsync(order);
            }
            else
            {
                // Log the ingredients for reference (but don't deduct stock yet)
                foreach (var ingredient in productElement.Ingredients)
                {
                    _logger.LogInformation($"Order includes {ingredient.Quantity * order.Quantity} {ingredient.Unit} of {ingredient.IngredientName} (will be deducted when completed)");
                }
                
                // Just create the order without updating stock
                // Stock will be updated when the order is marked as completed
                return await CreateOrderAsync(order);
            }
        }
    }
} 