using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using POS.Data;
using POS.Models;
using System.Collections.Concurrent;

namespace POS.Services
{
    public class LoginAttemptService : ILoginAttemptService
    {
        private readonly ApplicationDbContext _context;
        private readonly IMemoryCache _cache;
        
        // Make this static so it's shared across all instances of the service
        private static readonly ConcurrentDictionary<string, (int attempts, DateTime lockoutEnd)> _failedAttempts 
            = new ConcurrentDictionary<string, (int attempts, DateTime lockoutEnd)>();
            
        private const string LOGIN_SETTINGS_CACHE_KEY = "LoginSettings";

        public LoginAttemptService(ApplicationDbContext context, IMemoryCache cache)
        {
            _context = context;
            _cache = cache;
        }

        public async Task<LoginSettings> GetLoginSettingsAsync()
        {
            if (_cache.TryGetValue(LOGIN_SETTINGS_CACHE_KEY, out LoginSettings cachedSettings))
            {
                return cachedSettings;
            }

            var settings = await _context.LoginSettings
                .OrderByDescending(s => s.LastUpdated)
                .FirstOrDefaultAsync();
                
            if (settings == null)
            {
                settings = new LoginSettings();
                _context.LoginSettings.Add(settings);
                await _context.SaveChangesAsync();
            }

            // Cache settings for 5 minutes (reduced from 30 for more frequent updates)
            _cache.Set(LOGIN_SETTINGS_CACHE_KEY, settings, TimeSpan.FromMinutes(5));
            return settings;
        }

        public async Task SaveLoginSettingsAsync(LoginSettings settings, string updatedBy)
        {
            settings.LastUpdated = DateTime.Now;
            settings.UpdatedBy = updatedBy;

            _context.Update(settings);
            await _context.SaveChangesAsync();
            
            // Update cache
            _cache.Set(LOGIN_SETTINGS_CACHE_KEY, settings, TimeSpan.FromMinutes(30));
        }

        public async Task<bool> IsUserLockedOutAsync(string username)
        {
            if (string.IsNullOrEmpty(username))
                return false;

            var settings = await GetLoginSettingsAsync();
            if (!settings.EnableLockout)
                return false;

            if (_failedAttempts.TryGetValue(username, out var attemptInfo) && 
                attemptInfo.attempts >= settings.MaxLoginAttempts &&
                DateTime.Now < attemptInfo.lockoutEnd)
            {
                return true;
            }

            return false;
        }

        public async Task<(bool isLockedOut, TimeSpan timeRemaining)> RecordFailedAttemptAsync(string username)
        {
            if (string.IsNullOrEmpty(username))
                return (false, TimeSpan.Zero);

            var settings = await GetLoginSettingsAsync();
            if (!settings.EnableLockout)
                return (false, TimeSpan.Zero);

            // Get or initialize attempt info with 0 attempts and MinValue for lockout time
            var attemptInfo = _failedAttempts.GetOrAdd(username, (0, DateTime.MinValue));
            
            // Check if user is already locked out
            if (attemptInfo.attempts >= settings.MaxLoginAttempts && DateTime.Now < attemptInfo.lockoutEnd)
            {
                var timeRemaining = attemptInfo.lockoutEnd - DateTime.Now;
                return (true, timeRemaining);
            }

            // Increment failed attempts - create a new tuple to avoid value type issues
            int newAttempts = attemptInfo.attempts + 1;
            DateTime lockoutEnd = DateTime.MinValue;

            // If max attempts reached, set lockout time
            if (newAttempts >= settings.MaxLoginAttempts)
            {
                lockoutEnd = DateTime.Now.AddSeconds(settings.LockoutDuration);
            }

            // Update the record with the new tuple
            _failedAttempts[username] = (newAttempts, lockoutEnd);

            // Log the update for debugging
            Console.WriteLine($"User {username} failed login attempt: {newAttempts}/{settings.MaxLoginAttempts}");

            // If we've just locked out, return the lockout duration
            if (newAttempts >= settings.MaxLoginAttempts)
            {
                return (true, TimeSpan.FromSeconds(settings.LockoutDuration));
            }

            return (false, TimeSpan.Zero);
        }

        public Task ResetFailedAttemptsAsync(string username)
        {
            if (!string.IsNullOrEmpty(username))
            {
                _failedAttempts.TryRemove(username, out _);
            }
            
            return Task.CompletedTask;
        }
        
        public (int attempts, DateTime lockoutEnd) GetAttemptInfo(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                return (0, DateTime.MinValue);
            }
            
            // Use GetOrAdd to ensure consistency with RecordFailedAttemptAsync
            return _failedAttempts.GetOrAdd(username, (0, DateTime.MinValue));
        }

        public async Task<int> GetRemainingAttemptsAsync(string username)
        {
            var settings = await GetLoginSettingsAsync();
            var (attempts, _) = GetAttemptInfo(username);
            
            return Math.Max(0, settings.MaxLoginAttempts - attempts);
        }
    }
} 