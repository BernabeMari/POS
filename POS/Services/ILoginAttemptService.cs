using POS.Models;

namespace POS.Services
{
    public interface ILoginAttemptService
    {
        Task<LoginSettings> GetLoginSettingsAsync();
        Task SaveLoginSettingsAsync(LoginSettings settings, string updatedBy);
        Task<bool> IsUserLockedOutAsync(string username);
        Task<(bool isLockedOut, TimeSpan timeRemaining)> RecordFailedAttemptAsync(string username);
        Task ResetFailedAttemptsAsync(string username);
        (int attempts, DateTime lockoutEnd) GetAttemptInfo(string username);
        Task<int> GetRemainingAttemptsAsync(string username);
    }
} 