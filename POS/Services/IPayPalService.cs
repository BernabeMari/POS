using PayPalCheckoutSdk.Orders;
using System.Threading.Tasks;

namespace POS.Services
{
    public interface IPayPalService
    {
        Task<string> CreateOrder(decimal amount, string currency = "USD");
        Task<Order> CaptureOrder(string orderId);
    }
} 