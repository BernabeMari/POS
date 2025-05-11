using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Services;

namespace POS.Pages
{
    public class LockoutModel : PageModel
    {
        private readonly ILoginAttemptService _loginAttemptService;

        public TimeSpan RemainingLockoutTime { get; set; }

        public LockoutModel(ILoginAttemptService loginAttemptService)
        {
            _loginAttemptService = loginAttemptService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // Get the username from TempData (set in Login page)
            var username = TempData["LockedOutUser"]?.ToString();
            
            if (string.IsNullOrEmpty(username))
            {
                // If no locked out user was specified, redirect to login
                return RedirectToPage("/Login");
            }
            
            // Check if user is actually locked out and get remaining time
            var isLockedOut = await _loginAttemptService.IsUserLockedOutAsync(username);
            if (!isLockedOut)
            {
                // User is not locked out anymore, redirect to login
                return RedirectToPage("/Login");
            }
            
            // Get remaining lockout time from failed attempts tracker
            var (_, timeRemaining) = await _loginAttemptService.RecordFailedAttemptAsync(username);
            RemainingLockoutTime = timeRemaining;
            
            // Keep the username in TempData for potential redirects
            TempData["LockedOutUser"] = username;
            
            return Page();
        }
    }
} 