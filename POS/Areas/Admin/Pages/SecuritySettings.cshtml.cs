using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;

namespace POS.Areas.Admin.Pages
{
    [Authorize(Roles = "Admin")]
    public class SecuritySettingsModel : PageModel
    {
        private readonly IEncryptionService _encryptionService;
        private readonly UserManager<ApplicationUser> _userManager;

        public SecuritySettingsModel(
            IEncryptionService encryptionService,
            UserManager<ApplicationUser> userManager)
        {
            _encryptionService = encryptionService;
            _userManager = userManager;
        }

        [BindProperty]
        [Range(1, 25, ErrorMessage = "Shift value must be between 1 and 25")]
        [Display(Name = "Shift Value")]
        public int ShiftValue { get; set; }

        [TempData]
        public string SuccessMessage { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public void OnGet()
        {
            ShiftValue = _encryptionService.GetShiftValue();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            try
            {
                var user = await _userManager.GetUserAsync(User);
                string modifiedBy = user?.Email ?? "Admin";

                bool success = _encryptionService.UpdateShiftValue(ShiftValue, modifiedBy);

                if (success)
                {
                    SuccessMessage = "Encryption settings updated successfully.";
                }
                else
                {
                    ErrorMessage = "Failed to update encryption settings.";
                }
            }
            catch (Exception ex)
            {
                ErrorMessage = $"An error occurred: {ex.Message}";
            }

            return RedirectToPage();
        }
    }
} 