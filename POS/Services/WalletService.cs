using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace POS.Services
{
    public class WalletService : IWalletService
    {
        private readonly ApplicationDbContext _context;

        public WalletService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<decimal> GetBalanceAsync(string userId)
        {
            var wallet = await GetOrCreateWalletAsync(userId);
            return wallet.Balance;
        }

        public async Task<bool> HasSufficientFundsAsync(string userId, decimal amount)
        {
            var balance = await GetBalanceAsync(userId);
            return balance >= amount;
        }

        public async Task<WalletTransaction> TopUpAsync(string userId, decimal amount, string description)
        {
            if (amount <= 0)
                throw new ArgumentException("Amount must be greater than zero", nameof(amount));

            var wallet = await GetOrCreateWalletAsync(userId);
            decimal previousBalance = wallet.Balance;
            wallet.Balance += amount;
            wallet.UpdatedAt = DateTime.UtcNow;

            // Update the user's WalletBalance field too
            var user = await _context.Users.FindAsync(userId);
            if (user != null)
            {
                user.WalletBalance += amount;
                user.LastWalletTopUp = DateTime.UtcNow;
            }

            var transaction = new WalletTransaction
            {
                UserId = userId,
                Amount = amount,
                Description = description,
                Type = TransactionType.TopUp,
                Timestamp = DateTime.UtcNow,
                PreviousBalance = previousBalance,
                NewBalance = wallet.Balance,
                ReferenceNumber = Guid.NewGuid().ToString().Substring(0, 8)
            };

            _context.WalletTransactions.Add(transaction);
            await _context.SaveChangesAsync();

            return transaction;
        }

        public async Task<WalletTransaction> ProcessPaymentAsync(string userId, decimal amount, int orderId, string description)
        {
            if (amount <= 0)
                throw new ArgumentException("Amount must be greater than zero", nameof(amount));

            var wallet = await GetOrCreateWalletAsync(userId);
            
            if (wallet.Balance < amount)
                throw new InvalidOperationException("Insufficient funds");

            decimal previousBalance = wallet.Balance;
            wallet.Balance -= amount;
            wallet.UpdatedAt = DateTime.UtcNow;

            // Update the user's WalletBalance field too
            var user = await _context.Users.FindAsync(userId);
            if (user != null)
            {
                user.WalletBalance -= amount;
            }

            var transaction = new WalletTransaction
            {
                UserId = userId,
                Amount = -amount,
                OrderId = orderId,
                Description = description,
                Type = TransactionType.Payment,
                Timestamp = DateTime.UtcNow,
                PreviousBalance = previousBalance,
                NewBalance = wallet.Balance,
                ReferenceNumber = Guid.NewGuid().ToString().Substring(0, 8)
            };

            _context.WalletTransactions.Add(transaction);
            await _context.SaveChangesAsync();

            return transaction;
        }

        public async Task<WalletTransaction> ProcessRefundAsync(string userId, decimal amount, int orderId, string description)
        {
            if (amount <= 0)
                throw new ArgumentException("Amount must be greater than zero", nameof(amount));

            var wallet = await GetOrCreateWalletAsync(userId);
            decimal previousBalance = wallet.Balance;
            wallet.Balance += amount;
            wallet.UpdatedAt = DateTime.UtcNow;

            // Update the user's WalletBalance field too
            var user = await _context.Users.FindAsync(userId);
            if (user != null)
            {
                user.WalletBalance += amount;
            }

            var transaction = new WalletTransaction
            {
                UserId = userId,
                Amount = amount,
                OrderId = orderId,
                Description = description,
                Type = TransactionType.Refund,
                Timestamp = DateTime.UtcNow,
                PreviousBalance = previousBalance,
                NewBalance = wallet.Balance,
                ReferenceNumber = Guid.NewGuid().ToString().Substring(0, 8)
            };

            _context.WalletTransactions.Add(transaction);
            await _context.SaveChangesAsync();

            return transaction;
        }

        public async Task<IEnumerable<WalletTransaction>> GetTransactionHistoryAsync(string userId, int count = 10)
        {
            return await _context.WalletTransactions
                .Where(t => t.UserId == userId)
                .OrderByDescending(t => t.Timestamp)
                .Take(count)
                .ToListAsync();
        }

        public async Task<bool> AddFundsAsync(string userId, decimal amount)
        {
            try
            {
                await TopUpAsync(userId, amount, "Added funds to wallet");
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> MakePaymentAsync(string userId, decimal amount, string description)
        {
            try
            {
                await ProcessPaymentAsync(userId, amount, 0, description);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private async Task<Wallet> GetOrCreateWalletAsync(string userId)
        {
            var wallet = await _context.Wallets
                .FirstOrDefaultAsync(w => w.UserId == userId);

            if (wallet == null)
            {
                // Get the user to initialize with their current balance
                var user = await _context.Users.FindAsync(userId);
                decimal initialBalance = user?.WalletBalance ?? 0;

                wallet = new Wallet
                {
                    UserId = userId,
                    Balance = initialBalance,
                    CreatedAt = DateTime.UtcNow
                };
                _context.Wallets.Add(wallet);
                await _context.SaveChangesAsync();
            }

            return wallet;
        }
    }
} 