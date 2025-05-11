using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using POS.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace POS.Controllers.Api
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Employee")]
    public class StocksController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public StocksController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: api/stocks
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Stock>>> GetStocks()
        {
            try
            {
                var stocks = await _context.Stocks.ToListAsync();
                return Ok(stocks);
            }
            catch (InvalidOperationException ex)
            {
                // This could happen if the database connection has issues
                return StatusCode(500, $"Database connection error: {ex.Message}");
            }
            catch (DbUpdateException ex)
            {
                // Database update errors
                return StatusCode(500, $"Database error: {ex.Message}");
            }
            catch (Exception ex)
            {
                // Log inner exception if available for more details
                var message = ex.InnerException != null 
                    ? $"{ex.Message}, Inner exception: {ex.InnerException.Message}" 
                    : ex.Message;
                
                return StatusCode(500, $"Internal server error: {message}");
            }
        }

        // GET: api/stocks/5
        [HttpGet("{id}")]
        public async Task<ActionResult<Stock>> GetStock(int id)
        {
            try
            {
                var stock = await _context.Stocks.FindAsync(id);
                
                if (stock == null)
                {
                    return NotFound();
                }
                
                return Ok(stock);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // GET: api/stocks/lowstock
        [HttpGet("lowstock")]
        public async Task<ActionResult<IEnumerable<object>>> GetLowStockItems()
        {
            try
            {
                var lowStockItems = await _context.Stocks
                    .Where(s => s.Quantity < s.ThresholdLevel)
                    .Select(s => new {
                        s.StockID,
                        s.ProductName,
                        s.Category,
                        s.Quantity,
                        s.UnitType,
                        s.ThresholdLevel,
                        Status = s.Quantity <= 0 ? "Critical" : "Low"
                    })
                    .ToListAsync();
                    
                return Ok(lowStockItems);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // POST: api/stocks
        [HttpPost]
        public async Task<ActionResult<Stock>> CreateStock([FromBody] Stock stock)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }
                
                // Sanitize string inputs to prevent SQL injection
                stock.ProductName = SqlInputSanitizer.SanitizeString(stock.ProductName);
                stock.Category = SqlInputSanitizer.SanitizeString(stock.Category);
                stock.UnitType = SqlInputSanitizer.SanitizeString(stock.UnitType);
                stock.Notes = SqlInputSanitizer.SanitizeString(stock.Notes);
                
                // Set creation metadata
                stock.LastUpdated = DateTime.Now;
                stock.UpdatedBy = SqlInputSanitizer.SanitizeString(User.FindFirstValue(ClaimTypes.Name) ?? 
                    User.FindFirstValue(ClaimTypes.NameIdentifier));
                
                _context.Stocks.Add(stock);
                await _context.SaveChangesAsync();
                
                return CreatedAtAction(nameof(GetStock), new { id = stock.StockID }, stock);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // PUT: api/stocks/5
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateStock(int id, [FromBody] Stock stock)
        {
            try
            {
                if (id != stock.StockID)
                {
                    return BadRequest("ID mismatch");
                }
                
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }
                
                // Sanitize string inputs to prevent SQL injection
                stock.ProductName = SqlInputSanitizer.SanitizeString(stock.ProductName);
                stock.Category = SqlInputSanitizer.SanitizeString(stock.Category);
                stock.UnitType = SqlInputSanitizer.SanitizeString(stock.UnitType);
                stock.Notes = SqlInputSanitizer.SanitizeString(stock.Notes);
                
                // Update metadata
                stock.LastUpdated = DateTime.Now;
                stock.UpdatedBy = SqlInputSanitizer.SanitizeString(User.FindFirstValue(ClaimTypes.Name) ?? 
                    User.FindFirstValue(ClaimTypes.NameIdentifier));
                
                _context.Entry(stock).State = EntityState.Modified;
                
                try
                {
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!StockExists(id))
                    {
                        return NotFound();
                    }
                    throw;
                }
                
                return NoContent();
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // PATCH: api/stocks/5/quantity
        [HttpPatch("{id}/quantity")]
        public async Task<IActionResult> UpdateQuantity(int id, [FromBody] QuantityUpdateModel model)
        {
            try
            {
                var stock = await _context.Stocks.FindAsync(id);
                
                if (stock == null)
                {
                    return NotFound();
                }
                
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }
                
                // Get current user info
                var userName = SqlInputSanitizer.SanitizeString(User.FindFirstValue(ClaimTypes.Name) ?? 
                    User.FindFirstValue(ClaimTypes.NameIdentifier));
                
                // Sanitize inputs
                string sanitizedReason = SqlInputSanitizer.SanitizeString(model.Reason ?? "Quantity Update");
                string sanitizedNotes = SqlInputSanitizer.SanitizeString(model.Notes);
                
                // Create history record
                var history = new StockHistory
                {
                    StockID = id,
                    PreviousQuantity = stock.Quantity,
                    NewQuantity = model.NewQuantity,
                    ChangeReason = sanitizedReason,
                    ChangedBy = userName,
                    ChangeDate = DateTime.Now,
                    Notes = sanitizedNotes
                };
                
                // Update stock
                stock.Quantity = model.NewQuantity;
                stock.LastUpdated = DateTime.Now;
                stock.UpdatedBy = userName;
                stock.Notes = sanitizedNotes;
                
                // Add history record
                _context.StockHistory.Add(history);
                
                // Save all changes
                await _context.SaveChangesAsync();
                
                return Ok(new { 
                    success = true, 
                    message = "Stock quantity updated successfully" 
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // DELETE: api/stocks/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteStock(int id)
        {
            try
            {
                var stock = await _context.Stocks.FindAsync(id);
                
                if (stock == null)
                {
                    return NotFound();
                }
                
                // Check if there's any history for this stock
                var hasHistory = await _context.StockHistory.AnyAsync(h => h.StockID == id);
                if (hasHistory)
                {
                    return BadRequest("Cannot delete product with history records. Please archive it instead.");
                }
                
                _context.Stocks.Remove(stock);
                await _context.SaveChangesAsync();
                
                return NoContent();
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
        
        // GET: api/stocks/5/history
        [HttpGet("{id}/history")]
        public async Task<ActionResult<IEnumerable<StockHistory>>> GetStockHistory(int id)
        {
            try
            {
                var stock = await _context.Stocks.FindAsync(id);
                
                if (stock == null)
                {
                    return NotFound();
                }
                
                var history = await _context.StockHistory
                    .Where(h => h.StockID == id)
                    .OrderByDescending(h => h.ChangeDate)
                    .ToListAsync();
                
                return Ok(history);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
        
        private bool StockExists(int id)
        {
            return _context.Stocks.Any(e => e.StockID == id);
        }
    }
    
    public class QuantityUpdateModel
    {
        public decimal NewQuantity { get; set; }
        public string Reason { get; set; }
        public string Notes { get; set; }
    }
} 