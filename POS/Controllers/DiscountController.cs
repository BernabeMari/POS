using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using POS.Models;
using POS.Services;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using POS.Data;

namespace POS.Controllers
{
    [Authorize]
    public class DiscountController : Controller
    {
        private readonly IOrderService _orderService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<DiscountController> _logger;
        private readonly ApplicationDbContext _context;

        public DiscountController(
            IOrderService orderService,
            UserManager<ApplicationUser> userManager,
            ILogger<DiscountController> logger,
            ApplicationDbContext context)
        {
            _orderService = orderService;
            _userManager = userManager;
            _logger = logger;
            _context = context;
        }

        [HttpPost]
        public async Task<IActionResult> RequestDiscount(int orderId, string discountType)
        {
            _logger.LogInformation($"Discount request for order {orderId}, type: {discountType}");
            
            // Get the order
            var order = await _orderService.GetOrderByIdAsync(orderId);
            if (order == null)
            {
                _logger.LogWarning($"Order not found: {orderId}");
                return NotFound(new { success = false, message = "Order not found" });
            }
            
            // Check if discount already requested to prevent duplicate requests
            if (order.IsDiscountRequested)
            {
                _logger.LogInformation($"Discount already requested for order {orderId}, redirecting to pending page");
                
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { 
                        success = true, 
                        message = "Discount request already submitted. Please wait for manager approval.", 
                        order = order 
                    });
                }
                
                return RedirectToAction("DiscountPending", "Payment", new { orderId = orderId });
            }
            
            // Request discount
            var updatedOrder = await _orderService.RequestDiscountAsync(orderId, discountType);
            
            // Check if this is an AJAX request
            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                return Json(new { 
                    success = true, 
                    message = "Discount request submitted. Please wait for manager approval.", 
                    order = updatedOrder 
                });
            }
            
            TempData["SuccessMessage"] = "Discount request submitted. Please wait for manager approval.";
            return RedirectToAction("DiscountPending", "Payment", new { orderId = orderId });
        }
        
        [HttpGet]
        [Authorize(Roles = "Admin,Manager,Employee")]
        public async Task<IActionResult> PendingApprovals()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            
            // Check if user has Manager/Admin role OR Manager position or Assistant Manager with access
            bool isAuthorized = User.IsInRole("Admin") || User.IsInRole("Manager");
            
            if (!isAuthorized && User.IsInRole("Employee"))
            {
                // Check if this employee has Manager position or is an Assistant Manager with Manager access
                var user = await _context.Users
                    .Include(u => u.Position)
                    .FirstOrDefaultAsync(u => u.Id == userId);
                    
                if (user?.Position?.Name == "Manager")
                {
                    isAuthorized = true;
                }
                else if (user?.Position?.Name == "Assistant Manager")
                {
                    // Check if this Assistant Manager has been granted Manager dashboard access
                    isAuthorized = await _context.UserPreferences
                        .AnyAsync(p => p.UserId == userId && p.Key == "ManagerAccess" && p.Value == "true");
                }
            }
            
            if (!isAuthorized)
            {
                _logger.LogWarning($"User {userId} is not authorized to view pending discount approvals");
                return Forbid();
            }

            var orders = await _orderService.GetOrdersAwaitingDiscountApprovalAsync();
            return View(orders);
        }
        
        [HttpPost]
        [Authorize(Roles = "Admin,Manager,Employee")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApproveDiscount(int orderId)
        {
            _logger.LogInformation($"DiscountController.ApproveDiscount called with orderId: {orderId}");
            
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Check if user has Manager/Admin role OR Manager position
                bool isAuthorized = User.IsInRole("Admin") || User.IsInRole("Manager");
                
                if (!isAuthorized && User.IsInRole("Employee"))
                {
                    // Check if this employee has Manager position or is an Assistant Manager with Manager access
                    var user = await _context.Users
                        .Include(u => u.Position)
                        .FirstOrDefaultAsync(u => u.Id == userId);
                        
                    if (user?.Position?.Name == "Manager")
                    {
                        isAuthorized = true;
                    }
                    else if (user?.Position?.Name == "Assistant Manager")
                    {
                        // Check if this Assistant Manager has been granted Manager dashboard access
                        isAuthorized = await _context.UserPreferences
                            .AnyAsync(p => p.UserId == userId && p.Key == "ManagerAccess" && p.Value == "true");
                    }
                }
                
                if (!isAuthorized)
                {
                    _logger.LogWarning($"User {userId} is not authorized to approve discounts");
                    return Forbid();
                }
                
                _logger.LogInformation($"Approving discount for order {orderId} by manager {userId}");
                
                // Get the order
                var order = await _orderService.GetOrderByIdAsync(orderId);
                if (order == null)
                {
                    _logger.LogWarning($"Order not found: {orderId}");
                    return NotFound(new { success = false, message = "Order not found" });
                }
                
                // Approve discount (default 20%)
                var updatedOrder = await _orderService.ApproveDiscountAsync(orderId, userId);
                
                if (updatedOrder == null)
                {
                    _logger.LogError($"Failed to approve discount for order {orderId}");
                    return StatusCode(500, new { success = false, message = "Failed to approve discount" });
                }
                
                _logger.LogInformation($"Successfully approved discount for order {orderId}");
                
                // Check if this is an AJAX request
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { 
                        success = true, 
                        message = "Discount approved.", 
                        order = updatedOrder 
                    });
                }
                
                TempData["SuccessMessage"] = "Discount approved.";
                return RedirectToAction("PendingApprovals");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error approving discount for order {orderId}");
                return StatusCode(500, new { success = false, message = $"An error occurred: {ex.Message}" });
            }
        }
        
        [HttpPost]
        [Authorize(Roles = "Admin,Manager,Employee")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DenyDiscount(int orderId)
        {
            _logger.LogInformation($"DiscountController.DenyDiscount called with orderId: {orderId}");
            
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                
                // Check if user has Manager/Admin role OR Manager position
                bool isAuthorized = User.IsInRole("Admin") || User.IsInRole("Manager");
                
                if (!isAuthorized && User.IsInRole("Employee"))
                {
                    // Check if this employee has Manager position or is an Assistant Manager with Manager access
                    var user = await _context.Users
                        .Include(u => u.Position)
                        .FirstOrDefaultAsync(u => u.Id == userId);
                        
                    if (user?.Position?.Name == "Manager")
                    {
                        isAuthorized = true;
                    }
                    else if (user?.Position?.Name == "Assistant Manager")
                    {
                        // Check if this Assistant Manager has been granted Manager dashboard access
                        isAuthorized = await _context.UserPreferences
                            .AnyAsync(p => p.UserId == userId && p.Key == "ManagerAccess" && p.Value == "true");
                    }
                }
                
                if (!isAuthorized)
                {
                    _logger.LogWarning($"User {userId} is not authorized to deny discounts");
                    return Forbid();
                }
                
                _logger.LogInformation($"Denying discount for order {orderId} by manager {userId}");
                
                // Get the order
                var order = await _orderService.GetOrderByIdAsync(orderId);
                if (order == null)
                {
                    _logger.LogWarning($"Order not found: {orderId}");
                    return NotFound(new { success = false, message = "Order not found" });
                }
                
                // Deny discount
                var updatedOrder = await _orderService.DenyDiscountAsync(orderId, userId);
                
                if (updatedOrder == null)
                {
                    _logger.LogError($"Failed to deny discount for order {orderId}");
                    return StatusCode(500, new { success = false, message = "Failed to deny discount" });
                }
                
                _logger.LogInformation($"Successfully denied discount for order {orderId}");
                
                // Check if this is an AJAX request
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { 
                        success = true, 
                        message = "Discount denied.", 
                        order = updatedOrder,
                        redirectUrl = Url.Action("DiscountDenied", "Payment", new { orderId = orderId })
                    });
                }
                
                TempData["SuccessMessage"] = "Discount denied.";
                
                // For customer-facing view, redirect to the DiscountDenied page
                if (User.IsInRole("Customer"))
                {
                    return RedirectToAction("DiscountDenied", "Payment", new { orderId = orderId });
                }
                
                // For admin/manager view, redirect back to the pending approvals list
                return RedirectToAction("PendingApprovals");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error denying discount for order {orderId}");
                return StatusCode(500, new { success = false, message = $"An error occurred: {ex.Message}" });
            }
        }
        
        [HttpGet]
        [HttpPost]
        [Authorize]
        public async Task<IActionResult> CheckDiscountStatus(int orderId)
        {
            var order = await _orderService.GetOrderByIdAsync(orderId);
            if (order == null)
            {
                return NotFound(new { success = false, message = "Order not found" });
            }
            
            // Check if order has been approved and needs redirection
            if (order.IsDiscountApproved && order.IsDiscountRequested)
            {
                // Return redirect info in JSON - client side will handle the redirection
                return Json(new { 
                    success = true, 
                    status = order.Status.ToString(),
                    isDiscountRequested = order.IsDiscountRequested,
                    isDiscountApproved = order.IsDiscountApproved,
                    discountAmount = order.DiscountAmount,
                    totalPrice = order.TotalPrice,
                    originalPrice = order.OriginalTotalPrice,
                    redirectMethod = "POST"
                });
            }
            
            // Check if discount was denied (isDiscountRequested = false after being set true)
            if (!order.IsDiscountRequested && order.Status == OrderStatus.Pending && 
                order.DiscountType == null && order.DiscountAmount == 0)
            {
                // Return redirect info to the denial page
                return Json(new { 
                    success = true,
                    status = "DeniedDiscount",
                    isDiscountRequested = false,
                    isDiscountApproved = false,
                    redirectUrl = Url.Action("DiscountDenied", "Payment", new { orderId = orderId }),
                    redirectMethod = "GET"
                });
            }
            
            return Json(new { 
                success = true, 
                status = order.Status.ToString(),
                isDiscountRequested = order.IsDiscountRequested,
                isDiscountApproved = order.IsDiscountApproved,
                discountAmount = order.DiscountAmount,
                totalPrice = order.TotalPrice,
                originalPrice = order.OriginalTotalPrice
            });
        }
    }
} 