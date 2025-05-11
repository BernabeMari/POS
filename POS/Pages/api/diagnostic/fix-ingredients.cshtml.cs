using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace POS.Pages.api.diagnostic
{
    public class FixIngredientsModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<FixIngredientsModel> _logger;

        public FixIngredientsModel(ApplicationDbContext context, ILogger<FixIngredientsModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var result = new DiagnosticResult();
            
            // 1. Get all products (page elements that are products)
            var allProductElements = await _context.PageElements
                .Where(e => e.IsProduct)
                .ToListAsync();
                
            result.TotalProducts = allProductElements.Count;
            _logger.LogInformation($"Found {result.TotalProducts} product elements");
            
            // 2. Get all products with explicitly loaded ingredients
            var productsWithIngredients = await _context.PageElements
                .Where(e => e.IsProduct)
                .Include(e => e.Ingredients)
                .ToListAsync();
                
            // 3. Count products with ingredients
            var productsWithIngredientsCount = productsWithIngredients
                .Count(p => p.Ingredients != null && p.Ingredients.Any());
                
            result.ProductsWithIngredients = productsWithIngredientsCount;
            _logger.LogInformation($"Found {result.ProductsWithIngredients} products with ingredients");
            
            // 4. Count how many ingredients in total
            var totalIngredients = productsWithIngredients
                .Where(p => p.Ingredients != null)
                .Sum(p => p.Ingredients.Count);
                
            result.TotalIngredients = totalIngredients;
            _logger.LogInformation($"Found {result.TotalIngredients} total ingredients");
            
            // 5. Get all stock items
            var allStockItems = await _context.Stocks.ToListAsync();
            result.TotalStockItems = allStockItems.Count;
            _logger.LogInformation($"Found {result.TotalStockItems} stock items");
            
            // 6. Check for ingredients without matching stock
            var ingredientsWithoutStock = new List<IngredientIssue>();
            foreach (var product in productsWithIngredients.Where(p => p.Ingredients != null && p.Ingredients.Any()))
            {
                foreach (var ingredient in product.Ingredients)
                {
                    // Check if there's a stock item with the same name
                    var matchingStock = allStockItems.FirstOrDefault(s => 
                        s.ProductName.ToLower() == ingredient.IngredientName.ToLower());
                        
                    if (matchingStock == null)
                    {
                        // Try to find a partial match
                        matchingStock = allStockItems.FirstOrDefault(s => 
                            s.ProductName.ToLower().Contains(ingredient.IngredientName.ToLower()) || 
                            ingredient.IngredientName.ToLower().Contains(s.ProductName.ToLower()));
                            
                        if (matchingStock != null)
                        {
                            ingredientsWithoutStock.Add(new IngredientIssue
                            {
                                ProductId = product.Id,
                                ProductName = product.ProductName,
                                IngredientId = ingredient.Id,
                                IngredientName = ingredient.IngredientName,
                                IssueType = "Partial Match",
                                StockName = matchingStock.ProductName,
                                StockId = matchingStock.StockID
                            });
                        }
                        else
                        {
                            ingredientsWithoutStock.Add(new IngredientIssue
                            {
                                ProductId = product.Id,
                                ProductName = product.ProductName,
                                IngredientId = ingredient.Id,
                                IngredientName = ingredient.IngredientName,
                                IssueType = "No Match",
                                StockName = null,
                                StockId = 0
                            });
                        }
                    }
                }
            }
            
            result.IngredientsWithoutStock = ingredientsWithoutStock;
            _logger.LogInformation($"Found {result.IngredientsWithoutStock.Count} ingredients without exact stock match");
            
            // 7. Get all stocks in database for reference
            result.StockItems = allStockItems.Select(s => new StockInfo
            {
                Id = s.StockID,
                Name = s.ProductName,
                Category = s.Category,
                Quantity = s.Quantity,
                Unit = s.UnitType,
                ThresholdLevel = s.ThresholdLevel
            }).ToList();
            
            return new JsonResult(result);
        }
        
        public async Task<IActionResult> OnPostFixMatchingAsync()
        {
            var result = new FixResult();
            
            // Get all products with explicitly loaded ingredients
            var productsWithIngredients = await _context.PageElements
                .Where(e => e.IsProduct)
                .Include(e => e.Ingredients)
                .ToListAsync();
            
            // Get all stock items
            var allStockItems = await _context.Stocks.ToListAsync();
            
            // Track how many ingredients we've fixed
            int fixedCount = 0;
            
            // For each ingredient, try to update its name to match the stock name exactly
            foreach (var product in productsWithIngredients.Where(p => p.Ingredients != null && p.Ingredients.Any()))
            {
                foreach (var ingredient in product.Ingredients)
                {
                    // Skip if we have an exact match already
                    if (allStockItems.Any(s => s.ProductName.ToLower() == ingredient.IngredientName.ToLower()))
                        continue;
                    
                    // Try to find a partial match
                    var matchingStock = allStockItems.FirstOrDefault(s => 
                        s.ProductName.ToLower().Contains(ingredient.IngredientName.ToLower()) || 
                        ingredient.IngredientName.ToLower().Contains(s.ProductName.ToLower()) ||
                        // Also match on words
                        ingredient.IngredientName.ToLower().Split(' ').Any(word => 
                            s.ProductName.ToLower().Contains(word) && word.Length > 3));
                    
                    if (matchingStock != null)
                    {
                        _logger.LogInformation($"Updating ingredient name from '{ingredient.IngredientName}' to '{matchingStock.ProductName}'");
                        
                        // Update the ingredient name to match the stock name exactly
                        result.Updates.Add(new IngredientUpdate
                        {
                            ProductId = product.Id,
                            ProductName = product.ProductName,
                            IngredientId = ingredient.Id,
                            OldName = ingredient.IngredientName,
                            NewName = matchingStock.ProductName
                        });
                        
                        ingredient.IngredientName = matchingStock.ProductName;
                        fixedCount++;
                    }
                }
            }
            
            // Save the changes
            await _context.SaveChangesAsync();
            
            result.Success = true;
            result.FixedCount = fixedCount;
            
            return new JsonResult(result);
        }
    }
    
    public class DiagnosticResult
    {
        public int TotalProducts { get; set; }
        public int ProductsWithIngredients { get; set; }
        public int TotalIngredients { get; set; }
        public int TotalStockItems { get; set; }
        public List<IngredientIssue> IngredientsWithoutStock { get; set; } = new List<IngredientIssue>();
        public List<StockInfo> StockItems { get; set; } = new List<StockInfo>();
    }
    
    public class IngredientIssue
    {
        public int ProductId { get; set; }
        public string ProductName { get; set; }
        public int IngredientId { get; set; }
        public string IngredientName { get; set; }
        public string IssueType { get; set; }
        public string StockName { get; set; }
        public int StockId { get; set; }
    }
    
    public class StockInfo
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Category { get; set; }
        public decimal Quantity { get; set; }
        public string Unit { get; set; }
        public decimal ThresholdLevel { get; set; }
    }
    
    public class FixResult
    {
        public bool Success { get; set; }
        public int FixedCount { get; set; }
        public List<IngredientUpdate> Updates { get; set; } = new List<IngredientUpdate>();
    }
    
    public class IngredientUpdate
    {
        public int ProductId { get; set; }
        public string ProductName { get; set; }
        public int IngredientId { get; set; }
        public string OldName { get; set; }
        public string NewName { get; set; }
    }
} 