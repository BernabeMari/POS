using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using POS.Data;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class TestDataController : ControllerBase
    {
        private readonly IOrderService _orderService;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<TestDataController> _logger;

        public TestDataController(IOrderService orderService, ApplicationDbContext context, ILogger<TestDataController> logger)
        {
            _orderService = orderService;
            _context = context;
            _logger = logger;
        }

        [HttpGet("create-discount-requests")]
        public async Task<IActionResult> CreateDiscountRequests()
        {
            // Only allow in development environment
            if (!HttpContext.Request.Host.Value.Contains("localhost") && 
                !HttpContext.Request.Host.Value.Contains("127.0.0.1"))
            {
                return BadRequest("This endpoint is only available in development environment");
            }

            try
            {
                // Get existing users
                var users = _context.Users.Take(3).ToList();
                if (!users.Any())
                {
                    return BadRequest("No users found in the database");
                }

                // Create sample orders with discount requests
                var createdOrders = new List<Order>();
                
                // Generate test orders
                foreach (var user in users)
                {
                    // Senior Citizen discount
                    var seniorOrder = new Order
                    {
                        UserId = user.Id,
                        ProductName = "Coffee and Pastry Set",
                        ProductImageUrl = "/images/products/coffee-pastry.jpg",
                        Price = 12.99m,
                        Quantity = 1,
                        TotalPrice = 12.99m,
                        OriginalTotalPrice = 12.99m,
                        IsDiscountRequested = true,
                        DiscountType = "SeniorCitizen",
                        Status = OrderStatus.AwaitingDiscountApproval,
                        CreatedAt = DateTime.Now.AddHours(-1),
                        Notes = "Sample senior citizen discount request for testing"
                    };
                    
                    // PWD discount
                    var pwdOrder = new Order
                    {
                        UserId = user.Id,
                        ProductName = "Lunch Special",
                        ProductImageUrl = "/images/products/lunch-special.jpg",
                        Price = 15.99m,
                        Quantity = 1,
                        TotalPrice = 15.99m,
                        OriginalTotalPrice = 15.99m,
                        IsDiscountRequested = true,
                        DiscountType = "PWD",
                        Status = OrderStatus.AwaitingDiscountApproval,
                        CreatedAt = DateTime.Now.AddMinutes(-30),
                        Notes = "Sample PWD discount request for testing"
                    };
                    
                    _context.Orders.Add(seniorOrder);
                    _context.Orders.Add(pwdOrder);
                    
                    createdOrders.Add(seniorOrder);
                    createdOrders.Add(pwdOrder);
                }
                
                await _context.SaveChangesAsync();
                
                return Ok(new { 
                    message = $"Created {createdOrders.Count} discount requests for testing", 
                    orderIds = createdOrders.Select(o => o.Id).ToList() 
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating test discount requests");
                return StatusCode(500, new { error = "Failed to create test discount requests" });
            }
        }
    }
} 