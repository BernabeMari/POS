using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;

namespace POS.Services
{
    public class StockService : IStockService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<StockService> _logger;

        public StockService(ApplicationDbContext context, ILogger<StockService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<Stock> GetStockByNameAsync(string ingredientName)
        {
            // Sanitize the input to prevent SQL injection
            string sanitizedName = SqlInputSanitizer.SanitizeString(ingredientName);
            
            if (string.IsNullOrEmpty(sanitizedName))
            {
                _logger.LogWarning("Empty or invalid ingredient name provided");
                return null;
            }
            
            // First try exact case-insensitive match with sanitized input using StringComparison.OrdinalIgnoreCase
            var stock = await _context.Stocks
                .FirstOrDefaultAsync(s => EF.Functions.Collate(s.ProductName, "SQL_Latin1_General_CP1_CI_AS") == sanitizedName);
            
            if (stock != null)
            {
                _logger.LogInformation($"Found exact match for ingredient '{sanitizedName}' with stock item '{stock.ProductName}'");
                return stock;
            }
            
            // If no exact match, try contains match (check if stock product name contains the ingredient name or vice versa)
            stock = await _context.Stocks
                .FirstOrDefaultAsync(s => 
                    s.ProductName.ToLower().Contains(sanitizedName.ToLower()) || 
                    sanitizedName.ToLower().Contains(s.ProductName.ToLower()));
            
            if (stock != null)
            {
                _logger.LogInformation($"Found partial match for ingredient '{sanitizedName}' with stock item '{stock.ProductName}'");
                return stock;
            }
            
            // No match found
            _logger.LogWarning($"No stock found for ingredient: {sanitizedName}");
            return null;
        }

        public async Task<IEnumerable<Stock>> GetAllStocksAsync()
        {
            return await _context.Stocks
                .OrderBy(s => s.Category)
                .ThenBy(s => s.ProductName)
                .ToListAsync();
        }

        public async Task<IEnumerable<Stock>> GetLowStockItemsAsync()
        {
            return await _context.Stocks
                .Where(s => s.Quantity <= s.ThresholdLevel)
                .OrderBy(s => s.Quantity)
                .ToListAsync();
        }

        public async Task<Stock> AddStockAsync(Stock stock)
        {
            stock.LastUpdated = DateTime.Now;
            _context.Stocks.Add(stock);
            await _context.SaveChangesAsync();
            
            // Create stock history record
            var history = new StockHistory
            {
                StockID = stock.StockID,
                PreviousQuantity = 0,
                NewQuantity = stock.Quantity,
                ChangeReason = "Initial Stock Creation",
                ChangedBy = stock.UpdatedBy,
                ChangeDate = DateTime.Now,
                Notes = "Initial stock created"
            };
            
            await AddStockHistoryAsync(history);
            
            return stock;
        }

        public async Task<Stock> UpdateStockAsync(Stock stock)
        {
            var existingStock = await _context.Stocks.FindAsync(stock.StockID);
            if (existingStock == null)
                return null;
                
            // Create stock history record
            var history = new StockHistory
            {
                StockID = stock.StockID,
                PreviousQuantity = existingStock.Quantity,
                NewQuantity = stock.Quantity,
                ChangeReason = "Manual Update",
                ChangedBy = stock.UpdatedBy,
                ChangeDate = DateTime.Now,
                Notes = stock.Notes
            };
            
            // Update stock properties
            existingStock.ProductName = stock.ProductName;
            existingStock.Category = stock.Category;
            existingStock.Quantity = stock.Quantity;
            existingStock.UnitType = stock.UnitType;
            existingStock.ThresholdLevel = stock.ThresholdLevel;
            existingStock.LastUpdated = DateTime.Now;
            existingStock.UpdatedBy = stock.UpdatedBy;
            existingStock.Notes = stock.Notes;
            
            await _context.SaveChangesAsync();
            
            // Save history
            await AddStockHistoryAsync(history);
            
            return existingStock;
        }

        public async Task<bool> DeleteStockAsync(int stockId)
        {
            var stock = await _context.Stocks.FindAsync(stockId);
            if (stock == null)
                return false;
                
            _context.Stocks.Remove(stock);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeductIngredientStockAsync(string ingredientName, decimal quantity, string unitType, string reason = "Order")
        {
            _logger.LogInformation($"[STOCK-DEBUG] Deducting {quantity} {unitType} of ingredient '{ingredientName}' from stock for {reason}");
            
            try
            {
                // First, try exact match (case insensitive)
                var exactStock = await _context.Stocks
                    .FirstOrDefaultAsync(s => EF.Functions.Collate(s.ProductName, "SQL_Latin1_General_CP1_CI_AS") == ingredientName);
                
                if (exactStock != null)
                {
                    _logger.LogInformation($"[STOCK-DEBUG] Found exact match for ingredient '{ingredientName}' with stock item '{exactStock.ProductName}'");
                    return await DeductFromSpecificStock(exactStock, quantity, unitType, reason);
                }
                
                // Try partial match if exact match fails
                var partialStock = await _context.Stocks
                    .FirstOrDefaultAsync(s => 
                        s.ProductName.ToLower().Contains(ingredientName.ToLower()) || 
                        ingredientName.ToLower().Contains(s.ProductName.ToLower()));
                
                if (partialStock != null)
                {
                    _logger.LogInformation($"[STOCK-DEBUG] Found partial match for ingredient '{ingredientName}' with stock item '{partialStock.ProductName}'");
                    return await DeductFromSpecificStock(partialStock, quantity, unitType, reason);
                }
                
                // Try fuzzy matching as a last resort
                var allStocks = await _context.Stocks.ToListAsync();
                var bestMatch = allStocks
                    .Where(s => 
                        LevenshteinDistance(s.ProductName.ToLower(), ingredientName.ToLower()) <= 3 ||
                        s.ProductName.ToLower().Split(' ').Any(word => 
                            ingredientName.ToLower().Contains(word) && word.Length > 3))
                    .OrderBy(s => LevenshteinDistance(s.ProductName.ToLower(), ingredientName.ToLower()))
                    .FirstOrDefault();
                
                if (bestMatch != null)
                {
                    _logger.LogInformation($"[STOCK-DEBUG] Found fuzzy match for ingredient '{ingredientName}' with stock item '{bestMatch.ProductName}'");
                    return await DeductFromSpecificStock(bestMatch, quantity, unitType, reason);
                }
                
                // No match found after all attempts
                _logger.LogWarning($"[STOCK-DEBUG] No matching stock found for ingredient: {ingredientName}");
                
                // Log all available stock items for debugging
                var stockItems = await _context.Stocks.Select(s => s.ProductName).ToListAsync();
                _logger.LogInformation($"[STOCK-DEBUG] Available stock items: {string.Join(", ", stockItems)}");
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"[STOCK-DEBUG] Error deducting ingredient {ingredientName} from stock: {ex.Message}");
                return false;
            }
        }
        
        // Helper method to deduct from a specific stock item
        private async Task<bool> DeductFromSpecificStock(Stock stock, decimal quantity, string unitType, string reason)
        {
            try
            {
                // Check if units match and convert if needed
                decimal convertedQuantity = quantity;
                bool conversionNeeded = !string.Equals(stock.UnitType, unitType, StringComparison.OrdinalIgnoreCase);
                
                if (conversionNeeded)
                {
                    // Try to convert between units
                    bool conversionSuccessful = TryConvertUnits(
                        quantity, 
                        fromUnit: unitType, 
                        toUnit: stock.UnitType, 
                        out convertedQuantity
                    );
                    
                    if (!conversionSuccessful)
                    {
                        _logger.LogWarning($"[STOCK-DEBUG] Unit conversion failed: Cannot convert from {unitType} to {stock.UnitType}");
                        return false;
                    }
                    
                    _logger.LogInformation($"[STOCK-DEBUG] Converted {quantity} {unitType} to {convertedQuantity} {stock.UnitType}");
                }
                
                // Check if there's enough stock
                if (stock.Quantity < convertedQuantity)
                {
                    _logger.LogWarning($"[STOCK-DEBUG] Not enough stock for {stock.ProductName}: Available {stock.Quantity} {stock.UnitType}, Requested {convertedQuantity} {stock.UnitType}");
                    return false;
                }
                
                // Log the deduction details
                _logger.LogInformation($"[STOCK-DEBUG] Deducting {convertedQuantity} {stock.UnitType} from {stock.ProductName} (previous quantity: {stock.Quantity})");
                
                // Create history record
                var history = new StockHistory
                {
                    StockID = stock.StockID,
                    PreviousQuantity = stock.Quantity,
                    NewQuantity = stock.Quantity - convertedQuantity,
                    ChangeReason = reason,
                    ChangedBy = "System",
                    ChangeDate = DateTime.Now,
                    Notes = $"Automatic deduction due to {reason}" + (conversionNeeded ? $" (Converted from {quantity} {unitType})" : "")
                };
                
                // Update stock
                stock.Quantity -= convertedQuantity;
                stock.LastUpdated = DateTime.Now;
                stock.UpdatedBy = "System";
                stock.Notes = $"Last updated due to {reason}";
                
                await _context.SaveChangesAsync();
                
                try
                {
                    // Save history as a separate operation
                    await AddStockHistoryAsync(history);
                }
                catch (Exception historyEx)
                {
                    // Log but don't fail the operation if history recording fails
                    _logger.LogError(historyEx, $"[STOCK-DEBUG] Failed to record stock history for {stock.ProductName}, but stock was updated successfully");
                }
                
                // Check if stock is low after deduction
                if (stock.Quantity <= stock.ThresholdLevel)
                {
                    _logger.LogWarning($"[STOCK-DEBUG] Low stock alert: {stock.ProductName} is below threshold ({stock.Quantity} remaining)");
                    // Could trigger notifications here
                }
                
                _logger.LogInformation($"[STOCK-DEBUG] Successfully deducted stock for {stock.ProductName}. New quantity: {stock.Quantity} {stock.UnitType}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"[STOCK-DEBUG] Error deducting from stock {stock.ProductName}: {ex.Message}");
                return false;
            }
        }
        
        // Levenshtein Distance algorithm for fuzzy matching
        private static int LevenshteinDistance(string s, string t)
        {
            if (string.IsNullOrEmpty(s))
            {
                return string.IsNullOrEmpty(t) ? 0 : t.Length;
            }

            if (string.IsNullOrEmpty(t))
            {
                return s.Length;
            }

            int[] v0 = new int[t.Length + 1];
            int[] v1 = new int[t.Length + 1];

            for (int i = 0; i < v0.Length; i++)
            {
                v0[i] = i;
            }

            for (int i = 0; i < s.Length; i++)
            {
                v1[0] = i + 1;

                for (int j = 0; j < t.Length; j++)
                {
                    int cost = (s[i] == t[j]) ? 0 : 1;
                    v1[j + 1] = Math.Min(Math.Min(v1[j] + 1, v0[j + 1] + 1), v0[j] + cost);
                }

                for (int j = 0; j < v0.Length; j++)
                {
                    v0[j] = v1[j];
                }
            }

            return v1[t.Length];
        }

        // Helper method to convert between common units
        private bool TryConvertUnits(decimal quantity, string fromUnit, string toUnit, out decimal result)
        {
            // Convert both units to lowercase for case-insensitive comparison
            fromUnit = fromUnit.ToLower();
            toUnit = toUnit.ToLower();
            
            // If units are already the same, no conversion needed
            if (fromUnit == toUnit)
            {
                result = quantity;
                return true;
            }
            
            // Weight conversions
            if ((fromUnit == "g" || fromUnit == "gram" || fromUnit == "grams") && 
                (toUnit == "kg" || toUnit == "kilogram" || toUnit == "kilograms"))
            {
                result = quantity / 1000m; // grams to kilograms
                return true;
            }
            
            if ((fromUnit == "kg" || fromUnit == "kilogram" || toUnit == "kilograms") && 
                (toUnit == "g" || toUnit == "gram" || toUnit == "grams"))
            {
                result = quantity * 1000m; // kilograms to grams
                return true;
            }
            
            // Volume conversions
            if ((fromUnit == "ml" || fromUnit == "milliliter" || fromUnit == "milliliters") && 
                (toUnit == "l" || toUnit == "liter" || toUnit == "liters"))
            {
                result = quantity / 1000m; // milliliters to liters
                return true;
            }
            
            if ((fromUnit == "l" || fromUnit == "liter" || fromUnit == "liters") && 
                (toUnit == "ml" || toUnit == "milliliter" || toUnit == "milliliters"))
            {
                result = quantity * 1000m; // liters to milliliters
                return true;
            }
            
            // Cup conversions (approximate)
            if (fromUnit == "cup" || fromUnit == "cups")
            {
                if (toUnit == "ml" || toUnit == "milliliter" || toUnit == "milliliters")
                {
                    result = quantity * 240m; // cups to milliliters (approximate)
                    return true;
                }
                else if (toUnit == "l" || toUnit == "liter" || toUnit == "liters")
                {
                    result = quantity * 0.24m; // cups to liters (approximate)
                    return true;
                }
            }
            
            if (toUnit == "cup" || toUnit == "cups")
            {
                if (fromUnit == "ml" || fromUnit == "milliliter" || fromUnit == "milliliters")
                {
                    result = quantity / 240m; // milliliters to cups (approximate)
                    return true;
                }
                else if (fromUnit == "l" || fromUnit == "liter" || fromUnit == "liters")
                {
                    result = quantity * 4.17m; // liters to cups (approximate)
                    return true;
                }
            }
            
            // Spoon measurements (approximate)
            if (fromUnit == "tbsp" || fromUnit == "tablespoon" || fromUnit == "tablespoons")
            {
                if (toUnit == "ml" || toUnit == "milliliter" || toUnit == "milliliters")
                {
                    result = quantity * 15m; // tablespoons to milliliters (approximate)
                    return true;
                }
            }
            
            if (toUnit == "tbsp" || toUnit == "tablespoon" || toUnit == "tablespoons")
            {
                if (fromUnit == "ml" || fromUnit == "milliliter" || fromUnit == "milliliters")
                {
                    result = quantity / 15m; // milliliters to tablespoons (approximate)
                    return true;
                }
            }
            
            if (fromUnit == "tsp" || fromUnit == "teaspoon" || fromUnit == "teaspoons")
            {
                if (toUnit == "ml" || toUnit == "milliliter" || toUnit == "milliliters")
                {
                    result = quantity * 5m; // teaspoons to milliliters (approximate)
                    return true;
                }
                
                if (toUnit == "tbsp" || toUnit == "tablespoon" || toUnit == "tablespoons")
                {
                    result = quantity / 3m; // teaspoons to tablespoons
                    return true;
                }
            }
            
            if (toUnit == "tsp" || toUnit == "teaspoon" || toUnit == "teaspoons")
            {
                if (fromUnit == "ml" || fromUnit == "milliliter" || fromUnit == "milliliters")
                {
                    result = quantity / 5m; // milliliters to teaspoons (approximate)
                    return true;
                }
                
                if (fromUnit == "tbsp" || fromUnit == "tablespoon" || fromUnit == "tablespoons")
                {
                    result = quantity * 3m; // tablespoons to teaspoons
                    return true;
                }
            }
            
            // No known conversion found
            result = 0;
            return false;
        }

        public async Task<bool> UpdateStockForOrderAsync(PageElement productElement, int orderQuantity, string userId)
        {
            _logger.LogInformation($"Updating stock for product {productElement.ProductName}, order quantity: {orderQuantity}");
            
            if (productElement == null || !productElement.IsProduct)
            {
                _logger.LogWarning("Invalid product element provided");
                return false;
            }
            
            // Diagnostic information
            _logger.LogInformation($"Product details: ID={productElement.Id}, Name={productElement.ProductName}, IsProduct={productElement.IsProduct}");
            
            // Log stock information for diagnostics
            _logger.LogInformation("Current stock items in database:");
            var allStocks = await GetAllStocksAsync();
            foreach (var stock in allStocks)
            {
                _logger.LogInformation($"Stock: {stock.ProductName} ({stock.Quantity} {stock.UnitType})");
            }
            
            // Handle ingredients
            bool allIngredientsUpdated = true;
            
            // Make sure we have complete ingredient data
            if (productElement.Ingredients == null || !productElement.Ingredients.Any())
            {
                // Get fresh data directly from the database
                var refreshedElement = await _context.PageElements
                    .AsNoTracking()
                    .Include(e => e.Ingredients)
                    .FirstOrDefaultAsync(e => e.Id == productElement.Id);
                    
                if (refreshedElement != null && refreshedElement.Ingredients != null && refreshedElement.Ingredients.Any())
                {
                    _logger.LogInformation($"Using refreshed data: Found {refreshedElement.Ingredients.Count} ingredients for product {refreshedElement.ProductName}");
                    
                    // Process each ingredient separately
                    foreach (var ingredient in refreshedElement.Ingredients)
                    {
                        bool ingredientUpdated = await ProcessIngredientForOrder(ingredient, refreshedElement, orderQuantity);
                        if (!ingredientUpdated)
                        {
                            allIngredientsUpdated = false;
                        }
                    }
                }
                else
                {
                    _logger.LogWarning($"No ingredients found in database for product: {productElement.ProductName} (ID: {productElement.Id})");
                    allIngredientsUpdated = false;
                }
            }
            else
            {
                _logger.LogInformation($"Using provided data: Found {productElement.Ingredients.Count} ingredients for product {productElement.ProductName}");
                
                // Process ingredients from the provided product element
                foreach (var ingredient in productElement.Ingredients)
                {
                    bool ingredientUpdated = await ProcessIngredientForOrder(ingredient, productElement, orderQuantity);
                    if (!ingredientUpdated)
                    {
                        allIngredientsUpdated = false;
                    }
                }
            }
            
            return allIngredientsUpdated;
        }
        
        // Helper method to process a single ingredient for an order
        private async Task<bool> ProcessIngredientForOrder(ProductIngredient ingredient, PageElement productElement, int orderQuantity)
        {
            _logger.LogInformation($"Processing ingredient: {ingredient.IngredientName} ({ingredient.Quantity} {ingredient.Unit})");
            
            // Calculate total quantity needed for this order
            decimal totalQuantityNeeded = ingredient.Quantity * orderQuantity;
            
            // Try to find matching stock
            var matchingStock = await GetStockByNameAsync(ingredient.IngredientName);
            if (matchingStock != null)
            {
                _logger.LogInformation($"Found matching stock: {matchingStock.ProductName} with {matchingStock.Quantity} {matchingStock.UnitType} available");
            }
            else
            {
                _logger.LogWarning($"No matching stock found for ingredient: {ingredient.IngredientName}");
                
                // Try to suggest similar stock items
                var suggestedStocks = await FindSimilarStockItemsAsync(ingredient.IngredientName);
                if (suggestedStocks.Any())
                {
                    _logger.LogInformation("Similar stock items that might match:");
                    foreach (var stock in suggestedStocks)
                    {
                        _logger.LogInformation($"- {stock.ProductName} ({stock.Quantity} {stock.UnitType})");
                    }
                }
            }
            
            try
            {
                // Deduct from stock - Continue with other ingredients even if this one fails
                bool deducted = await DeductIngredientStockAsync(
                    ingredient.IngredientName,
                    totalQuantityNeeded,
                    ingredient.Unit,
                    $"Order for {productElement.ProductName}"
                );
                
                if (!deducted)
                {
                    _logger.LogWarning($"Failed to deduct stock for ingredient: {ingredient.IngredientName}");
                    return false;
                }
                else
                {
                    _logger.LogInformation($"Successfully deducted {totalQuantityNeeded} {ingredient.Unit} of {ingredient.IngredientName}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deducting stock for ingredient {ingredient.IngredientName}: {ex.Message}");
                // Continue with other ingredients
                return false;
            }
        }

        // Helper method to find similar stock items when no exact match is found
        private async Task<List<Stock>> FindSimilarStockItemsAsync(string ingredientName)
        {
            // Convert ingredient name to lowercase for case-insensitive comparison
            var ingredientLower = ingredientName.ToLower();
            
            // Get all stocks
            var allStocks = await GetAllStocksAsync();
            
            // Find stocks with similar names (containing at least part of the ingredient name)
            var similarStocks = allStocks
                .Where(s => 
                    // Check for partial matches in either direction
                    s.ProductName.ToLower().Contains(ingredientLower) || 
                    ingredientLower.Contains(s.ProductName.ToLower()) ||
                    // Check for word-level matches
                    ingredientLower.Split(' ').Any(word => 
                        s.ProductName.ToLower().Contains(word) && word.Length > 3) || // Only match on words with >3 chars
                    s.ProductName.ToLower().Split(' ').Any(word => 
                        ingredientLower.Contains(word) && word.Length > 3)
                )
                .OrderBy(s => s.ProductName)
                .ToList();
            
            return similarStocks;
        }

        public async Task<StockHistory> AddStockHistoryAsync(StockHistory stockHistory)
        {
            _context.StockHistory.Add(stockHistory);
            await _context.SaveChangesAsync();
            return stockHistory;
        }
    }
} 