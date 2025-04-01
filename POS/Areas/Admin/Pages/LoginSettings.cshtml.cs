using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;

namespace POS.Areas.Admin.Pages
{
    public class LoginSettingsModel : PageModel
    {
        private readonly ILoginAttemptService _loginAttemptService;

        [BindProperty]
        public LoginSettings Settings { get; set; }

        [TempData]
        public string SuccessMessage { get; set; }

        public LoginSettingsModel(ILoginAttemptService loginAttemptService)
        {
            _loginAttemptService = loginAttemptService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            Settings = await _loginAttemptService.GetLoginSettingsAsync();
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            await _loginAttemptService.SaveLoginSettingsAsync(Settings, User.Identity.Name);
            
            SuccessMessage = "Login security settings have been updated successfully.";
            return RedirectToPage();
        }
    }
} 