using Microsoft.Extensions.Configuration;
using PayPalCheckoutSdk.Core;
using PayPalCheckoutSdk.Orders;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace POS.Services
{
    public class PayPalService : IPayPalService
    {
        private readonly IConfiguration _configuration;
        private readonly PayPalHttpClient _client;

        public PayPalService(IConfiguration configuration)
        {
            _configuration = configuration;
            
            // Create a PayPal environment with sandbox credentials
            var environment = new SandboxEnvironment(
                _configuration["PayPal:ClientId"],
                _configuration["PayPal:ClientSecret"]);
                
            _client = new PayPalHttpClient(environment);
        }
        
        public async Task<string> CreateOrder(decimal amount, string currency = "USD")
        {
            // Validate the amount - PayPal requires positive values
            if (amount <= 0)
            {
                throw new ArgumentException("Payment amount must be greater than zero");
            }
            
            // Create the order request
            var orderRequest = new OrderRequest()
            {
                CheckoutPaymentIntent = "CAPTURE",
                PurchaseUnits = new List<PurchaseUnitRequest>()
                {
                    new PurchaseUnitRequest()
                    {
                        AmountWithBreakdown = new AmountWithBreakdown()
                        {
                            CurrencyCode = currency,
                            Value = amount.ToString("0.00")
                        }
                    }
                },
                ApplicationContext = new ApplicationContext()
                {
                    ReturnUrl = _configuration["PayPal:ReturnUrl"],
                    CancelUrl = _configuration["PayPal:CancelUrl"]
                }
            };
            
            // Create the order
            var request = new OrdersCreateRequest();
            request.Prefer("return=representation");
            request.RequestBody(orderRequest);
            
            try
            {
                var response = await _client.Execute(request);
                var order = response.Result<Order>();
                
                // Return the approval URL
                foreach (var link in order.Links)
                {
                    if (link.Rel == "approve")
                    {
                        return link.Href;
                    }
                }
                
                throw new Exception("No approval URL found in PayPal response");
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to create PayPal order: {ex.Message}");
            }
        }
        
        public async Task<Order> CaptureOrder(string orderId)
        {
            var request = new OrdersCaptureRequest(orderId);
            request.Prefer("return=representation");
            
            try
            {
                var response = await _client.Execute(request);
                return response.Result<Order>();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to capture PayPal order: {ex.Message}");
            }
        }
    }
} 