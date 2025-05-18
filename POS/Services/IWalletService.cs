using POS.Models;

namespace POS.Services
{
    public interface IWalletService
    {
        Task<decimal> GetBalanceAsync(string userId);
        Task<WalletTransaction> TopUpAsync(string userId, decimal amount, string description);
        Task<WalletTransaction> ProcessPaymentAsync(string userId, decimal amount, int orderId, string description);
        Task<WalletTransaction> ProcessRefundAsync(string userId, decimal amount, int orderId, string description);
        Task<IEnumerable<WalletTransaction>> GetTransactionHistoryAsync(string userId, int count = 10);
        Task<bool> HasSufficientFundsAsync(string userId, decimal amount);
        Task<bool> AddFundsAsync(string userId, decimal amount);
        Task<bool> MakePaymentAsync(string userId, decimal amount, string description);
    }
} 