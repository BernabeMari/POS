using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using POS.Models;
using POS.Services;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;

namespace POS.Controllers
{
    [Authorize]
    public class PaymentController : Controller
    {
        private readonly IPayPalService _paypalService;
        private readonly IOrderService _orderService;
        private readonly ICartService _cartService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<PaymentController> _logger;

        public PaymentController(
            IPayPalService paypalService,
            IOrderService orderService,
            ICartService cartService,
            UserManager<ApplicationUser> userManager,
            ILogger<PaymentController> logger)
        {
            _paypalService = paypalService;
            _orderService = orderService;
            _cartService = cartService;
            _userManager = userManager;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> CreatePayment(int orderId)
        {
            _logger.LogInformation($"CreatePayment action called with orderId: {orderId}");
            
            // Verify user is authenticated
            if (!User.Identity.IsAuthenticated)
            {
                _logger.LogWarning("User is not authenticated during payment process");
                TempData["ErrorMessage"] = "Please log in to complete your payment.";
                return RedirectToAction("Login", "Account", new { returnUrl = Url.Action("CreatePayment", "Payment", new { orderId = orderId }) });
            }
            
            // Get the order
            var order = await _orderService.GetOrderByIdAsync(orderId);
            if (order == null)
            {
                _logger.LogWarning($"Order not found: {orderId}");
                return NotFound();
            }
            
            // Get the user to check for discount eligibility
            var user = await _userManager.FindByIdAsync(order.UserId);
            if (user == null)
            {
                _logger.LogWarning($"User not found for order {orderId}");
                return NotFound();
            }
            
            // Check if user is eligible for discount and it hasn't been requested yet
            if (!order.IsDiscountRequested)
            {
                if (user.IsSeniorCitizen || user.IsPWD)
                {
                    // If the request is coming from the "Skip Discount" button on the discount page
                    // This is determined by looking at the referrer URL which should contain "DiscountRequest"
                    if (Request.Headers["Referer"].ToString().Contains("DiscountRequest") || 
                        Request.Headers["Referer"].ToString().Contains("DiscountPending"))
                    {
                        // User is explicitly skipping the discount
                        _logger.LogInformation($"User {user.Id} is skipping discount for order {orderId}");
                        order = await _orderService.SkipDiscountAsync(orderId);
                    }
                    else
                    {
                        // User is eligible for discount - show discount request page
                        _logger.LogInformation($"Redirecting user {user.Id} to discount request page for order {orderId}");
                        return RedirectToAction("DiscountRequest", new { orderId = orderId });
                    }
                }
            }
            
            // If discount is requested but not yet approved, redirect to a waiting page
            if (order.IsDiscountRequested && !order.IsDiscountApproved && 
                order.Status == OrderStatus.AwaitingDiscountApproval)
            {
                return RedirectToAction("DiscountPending", new { orderId = orderId });
            }

            // Get current cart items total
            decimal totalAmount = 0;
            
            // Get the cart items for this user
            var cartItems = await _cartService.GetCartItemsByUserIdAsync(order.UserId);
            
            if (cartItems != null && cartItems.Any())
            {
                // Calculate total from cart items
                totalAmount = await _cartService.GetCartTotalAsync(order.UserId);
                _logger.LogInformation($"Using cart total for payment: {totalAmount}");
            }
            else
            {
                // If cart is empty (direct purchase), use the specified order total
                totalAmount = order.TotalPrice;
                _logger.LogInformation($"Using direct order total for payment: {totalAmount} for order {order.Id}");
            }
            
            _logger.LogInformation($"Final order total for payment: {totalAmount}");
            
            // Check if the total amount is zero or less
            if (totalAmount <= 0)
            {
                _logger.LogWarning($"Cannot process payment with zero or negative amount: {totalAmount}");
                TempData["ErrorMessage"] = "Your cart appears to be empty or contains only free items. Please add items to your cart before proceeding to payment.";
                return RedirectToAction("Index", "Cart");
            }
            
            // Create PayPal order
            try
            {
                _logger.LogInformation($"Creating PayPal order for orderId: {orderId}, total amount: {totalAmount}");
                var approvalUrl = await _paypalService.CreateOrder(totalAmount);
                
                _logger.LogInformation($"PayPal approval URL: {approvalUrl}");
                
                // Store order ID in TempData instead of Session to avoid session corruption
                TempData["PaymentOrderId"] = orderId.ToString();
                
                // Check if this is an AJAX request
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    // Return JSON response with the redirect URL
                    return Json(new { redirectUrl = approvalUrl });
                }
                
                // Redirect to PayPal for approval (normal form submit)
                return Redirect(approvalUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError($"PayPal Error: {ex.Message}");
                TempData["ErrorMessage"] = $"PayPal Error: {ex.Message}";
                
                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return BadRequest(new { error = ex.Message });
                }
                
                return RedirectToAction("Details", "Orders", new { id = orderId });
            }
        }
        
        [HttpGet]
        public async Task<IActionResult> DiscountRequest(int orderId)
        {
            // Get the order
            var order = await _orderService.GetOrderByIdAsync(orderId);
            if (order == null)
            {
                _logger.LogWarning($"Order not found: {orderId}");
                return NotFound();
            }
            
            // Get user
            var user = await _userManager.FindByIdAsync(order.UserId);
            if (user == null)
            {
                return NotFound();
            }
            
            // For displaying cart items in the view
            var cartItems = await _cartService.GetCartItemsByUserIdAsync(user.Id);
            _logger.LogInformation($"Cart items count: {cartItems.Count()}");
            
            // Set default cart total
            decimal cartTotal = 0;
            
            // Check if this is a direct product order (cart might be empty)
            if (cartItems == null || !cartItems.Any())
            {
                _logger.LogInformation($"Cart is empty for user {user.Id}, this is likely a direct product purchase");
                
                // Create a temporary cart item from the order for display purposes
                cartItems = new List<CartItem> 
                {
                    new CartItem 
                    {
                        Id = 0,
                        UserId = user.Id,
                        ProductId = 0,
                        ProductName = order.ProductName,
                        Price = order.Price,
                        Quantity = order.Quantity,
                        ProductImageUrl = order.ProductImageUrl,
                        CreatedAt = DateTime.Now
                    }
                };
                
                // Use the order's total price
                cartTotal = order.TotalPrice;
            }
            else
            {
                // Calculate cart total from cart items
                cartTotal = await _cartService.GetCartTotalAsync(user.Id);
            }
            
            _logger.LogInformation($"Cart total value: {cartTotal}");
            
            // Display discount request page
            ViewBag.Order = order;
            ViewBag.User = user;
            ViewBag.CartItems = cartItems;
            ViewBag.CartTotal = cartTotal;
            ViewBag.DiscountOptions = new List<string>();
            
            if (user.IsSeniorCitizen)
            {
                ViewBag.DiscountOptions.Add("SeniorCitizen");
            }
            
            if (user.IsPWD)
            {
                ViewBag.DiscountOptions.Add("PWD");
            }
            
            return View();
        }
        
        [HttpGet]
        public async Task<IActionResult> DiscountPending(int orderId)
        {
            // Get the order
            var order = await _orderService.GetOrderByIdAsync(orderId);
            if (order == null)
            {
                _logger.LogWarning($"Order not found: {orderId}");
                return NotFound();
            }
            
            // If discount is already approved, proceed to payment
            if (order.IsDiscountApproved && order.Status == OrderStatus.Pending)
            {
                _logger.LogInformation($"Discount already approved for order {orderId}, proceeding to payment");
                return RedirectToAction("CreatePayment", new { orderId = orderId });
            }
            
            // Get cart items and total
            var cartItems = await _cartService.GetCartItemsByUserIdAsync(order.UserId);
            
            // Set default cart total
            decimal cartTotal = 0;
            
            // Check if this is a direct product order (cart might be empty)
            if (cartItems == null || !cartItems.Any())
            {
                _logger.LogInformation($"Cart is empty for user {order.UserId}, this is likely a direct product purchase");
                
                // Create a temporary cart item from the order for display purposes
                cartItems = new List<CartItem> 
                {
                    new CartItem 
                    {
                        Id = 0,
                        UserId = order.UserId,
                        ProductId = 0,
                        ProductName = order.ProductName,
                        Price = order.Price,
                        Quantity = order.Quantity,
                        ProductImageUrl = order.ProductImageUrl,
                        CreatedAt = DateTime.Now
                    }
                };
                
                // Use the order's total price
                cartTotal = order.TotalPrice;
            }
            else
            {
                // Calculate cart total from cart items
                cartTotal = await _cartService.GetCartTotalAsync(order.UserId);
            }
            
            // Display waiting page
            ViewBag.Order = order;
            ViewBag.CartItems = cartItems;
            ViewBag.CartTotal = cartTotal;
            return View();
        }
        
        [HttpPost]
        public async Task<IActionResult> GetPayPalRedirectUrl(int orderId)
        {
            _logger.LogInformation($"GetPayPalRedirectUrl called for orderId: {orderId}");
            
            try
            {
                // Get the order
                var order = await _orderService.GetOrderByIdAsync(orderId);
                if (order == null)
                {
                    _logger.LogWarning($"Order not found: {orderId}");
                    return NotFound(new { error = "Order not found" });
                }
                
                // Get current cart items total
                decimal totalAmount = 0;
                
                // Get the cart items for this user
                var cartItems = await _cartService.GetCartItemsByUserIdAsync(order.UserId);
                
                if (cartItems != null && cartItems.Any())
                {
                    // Calculate total from cart items
                    totalAmount = await _cartService.GetCartTotalAsync(order.UserId);
                    _logger.LogInformation($"Using cart total for payment: {totalAmount}");
                }
                else
                {
                    // If cart is empty (direct purchase), use the specified order total
                    totalAmount = order.TotalPrice;
                    _logger.LogInformation($"Using direct order total for payment: {totalAmount} for order {order.Id}");
                }
                
                _logger.LogInformation($"Final order total for payment: {totalAmount}");
                
                // Check if the total amount is zero or less
                if (totalAmount <= 0)
                {
                    _logger.LogWarning($"Cannot process payment with zero or negative amount: {totalAmount}");
                    return BadRequest(new { error = "Order total amount must be greater than zero" });
                }
                
                // Create PayPal order and get the approval URL
                var approvalUrl = await _paypalService.CreateOrder(totalAmount);
                
                _logger.LogInformation($"PayPal approval URL: {approvalUrl}");
                
                // Store order ID in TempData instead of Session to avoid session corruption
                TempData["PaymentOrderId"] = orderId.ToString();
                
                // Return the URL as JSON
                return Json(new { redirectUrl = approvalUrl });
            }
            catch (Exception ex)
            {
                _logger.LogError($"PayPal Error in GetPayPalRedirectUrl: {ex.Message}");
                return BadRequest(new { error = ex.Message });
            }
        }

        public async Task<IActionResult> CreatePaymentForm(int orderId)
        {
            // For GET requests, we'll render a form that will submit to the POST version
            // This is a workaround for HTTP 405 Method Not Allowed errors when redirecting
            
            _logger.LogInformation($"GET CreatePaymentForm action called with orderId: {orderId}");
            
            // Get the order
            var order = await _orderService.GetOrderByIdAsync(orderId);
            if (order == null)
            {
                _logger.LogWarning($"Order not found: {orderId}");
                return NotFound();
            }
            
            // Get the user to check for discount eligibility
            var user = await _userManager.FindByIdAsync(order.UserId);
            if (user == null)
            {
                _logger.LogWarning($"User not found for order {orderId}");
                return NotFound();
            }
            
            // Check if user is eligible for discount and it hasn't been requested yet
            if (!order.IsDiscountRequested)
            {
                if (user.IsSeniorCitizen || user.IsPWD)
                {
                    // If the request is coming from the "Skip Discount" button on the discount page
                    if (Request.Headers["Referer"].ToString().Contains("DiscountRequest") || 
                        Request.Headers["Referer"].ToString().Contains("DiscountPending"))
                    {
                        // User is explicitly skipping the discount
                        _logger.LogInformation($"User {user.Id} is skipping discount for order {orderId}");
                        order = await _orderService.SkipDiscountAsync(orderId);
                    }
                    else
                    {
                        // User is eligible for discount - show discount request page
                        _logger.LogInformation($"Redirecting user {user.Id} to discount request page for order {orderId}");
                        return RedirectToAction("DiscountRequest", new { orderId = orderId });
                    }
                }
            }
            
            // If discount is requested but not yet approved, redirect to a waiting page
            if (order.IsDiscountRequested && !order.IsDiscountApproved && 
                order.Status == OrderStatus.AwaitingDiscountApproval)
            {
                return RedirectToAction("DiscountPending", new { orderId = orderId });
            }

            // Render a view with a form that will POST to the CreatePayment action
            ViewBag.Order = order;
            return View("PaymentRedirect");
        }

        public async Task<IActionResult> Success(string token)
        {
            // Get order ID from TempData instead of Session
            var orderIdStr = TempData["PaymentOrderId"]?.ToString();
            if (string.IsNullOrEmpty(orderIdStr) || !int.TryParse(orderIdStr, out int orderId))
            {
                return RedirectToAction("Index", "Home");
            }

            try
            {
                // Capture the payment
                var paypalOrder = await _paypalService.CaptureOrder(token);
                
                // Get the order to retrieve the user ID
                var order = await _orderService.GetOrderByIdAsync(orderId);
                if (order == null)
                {
                    _logger.LogWarning($"Order not found: {orderId}");
                    TempData["ErrorMessage"] = "Order not found.";
                    return RedirectToAction("Index", "Home");
                }
                
                // Get all pending orders for this user
                var userOrders = await _orderService.GetOrdersByUserIdAsync(order.UserId);
                var pendingOrders = userOrders.Where(o => o.Status == OrderStatus.Pending).ToList();
                
                _logger.LogInformation($"Marking {pendingOrders.Count} orders as Paid for user {order.UserId}");
                
                // Update all pending orders to Paid status
                foreach (var pendingOrder in pendingOrders)
                {
                    await _orderService.UpdateOrderStatusAsync(pendingOrder.Id, OrderStatus.Paid);
                    _logger.LogInformation($"Order {pendingOrder.Id} marked as Paid");
                }
                
                // ONLY clear the cart after successful payment
                await _cartService.ClearCartAsync(order.UserId);
                _logger.LogInformation($"Cart cleared for user {order.UserId} after successful payment");
                
                // Clear the TempData
                TempData.Remove("PaymentOrderId");
                
                // Add success message to TempData
                TempData["SuccessMessage"] = "Payment completed successfully!";
                
                // Return a view with the order ID and payment token
                return View("Success", new PaymentSuccessViewModel
                {
                    OrderId = orderId,
                    PaymentToken = token
                });
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"Failed to process payment: {ex.Message}";
                return RedirectToAction("Details", "Orders", new { id = orderId });
            }
        }

        public async Task<IActionResult> Cancel()
        {
            // Get order ID from TempData instead of Session
            var orderIdStr = TempData["PaymentOrderId"]?.ToString();
            int? orderId = null;
            
            if (!string.IsNullOrEmpty(orderIdStr) && int.TryParse(orderIdStr, out int parsedOrderId))
            {
                orderId = parsedOrderId;
            }
            
            _logger.LogInformation($"Payment cancelled for orderId: {orderId}");
            
            if (orderId.HasValue)
            {
                // Update the order status to Cancelled
                await _orderService.UpdateOrderStatusAsync(orderId.Value, OrderStatus.Cancelled);
                
                // Clean up TempData
                TempData.Remove("PaymentOrderId");
                TempData["ErrorMessage"] = "Payment was cancelled. Your order will not be processed.";
                TempData["CancelledCheckout"] = "true"; // Flag to notify frontend to clear the overlay
                TempData["PreventCartClear"] = "true"; // Flag to prevent cart from being cleared
                
                // Add JavaScript to immediately fix the overlay (executed before page fully loads)
                TempData["FixOverlayScript"] = @"
                    window.onload = function() {
                        const overlay = document.getElementById('checkoutOverlay');
                        if (overlay) {
                            overlay.style.display = 'none';
                            overlay.style.visibility = 'hidden';
                            overlay.style.opacity = '0';
                            console.log('Overlay hidden by direct script');
                        }

                        // Clear any navigation blockers
                        window.removeEventListener('beforeunload', window.preventNavigation);
                        sessionStorage.removeItem('checkoutInProgress');
                    };
                ";
                
                // Redirect back to the user dashboard instead of cart
                return RedirectToAction("Index", "User", new { area = "User" });
            }
            
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public async Task<IActionResult> DiscountDenied(int orderId, string reason = null)
        {
            // Get the order
            var order = await _orderService.GetOrderByIdAsync(orderId);
            if (order == null)
            {
                _logger.LogWarning($"Order not found: {orderId}");
                return NotFound();
            }
            
            // Get cart items and total
            var cartItems = await _cartService.GetCartItemsByUserIdAsync(order.UserId);
            decimal cartTotal = await _cartService.GetCartTotalAsync(order.UserId);
            
            // Display discount denied page with options
            ViewBag.Order = order;
            ViewBag.CartItems = cartItems;
            ViewBag.CartTotal = cartTotal;
            ViewBag.DenialReason = reason;
            return View();
        }
    }
} 