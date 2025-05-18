using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using POS.Services;
using System;
using System.Threading.Tasks;

namespace POS.Controllers
{
    public class TestController : Controller
    {
        private readonly IPayPalService _paypalService;
        private readonly ILogger<TestController> _logger;

        public TestController(
            IPayPalService paypalService,
            ILogger<TestController> logger)
        {
            _paypalService = paypalService;
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public async Task<IActionResult> TestPayPal()
        {
            try
            {
                _logger.LogInformation("Testing PayPal integration");
                
                // Create a test order for $1.00
                var approvalUrl = await _paypalService.CreateOrder(1.00m);
                
                _logger.LogInformation($"PayPal approval URL: {approvalUrl}");
                
                // Store test data in session
                HttpContext.Session.SetString("TestPayPal", "true");
                
                // Redirect to PayPal
                return Redirect(approvalUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError($"PayPal test error: {ex.Message}");
                return Content($"Error testing PayPal: {ex.Message}");
            }
        }

        public IActionResult Success(string token)
        {
            try
            {
                _logger.LogInformation($"PayPal test success with token: {token}");
                
                // Add a success message to TempData
                TempData["SuccessMessage"] = "Payment completed successfully!";
                
                // Return a view with auto-redirect
                return View("Success", token);
            }
            catch (Exception ex)
            {
                _logger.LogError($"PayPal success error: {ex.Message}");
                TempData["ErrorMessage"] = $"Error in payment process: {ex.Message}";
                return RedirectToAction("Index", "Home");
            }
        }

        public IActionResult Cancel()
        {
            _logger.LogInformation("PayPal test cancelled");
            return Content("PayPal test cancelled by user");
        }
    }
} 