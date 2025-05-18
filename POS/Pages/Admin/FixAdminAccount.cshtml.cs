using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using POS.Services;
using System.Text;

namespace POS.Pages.Admin
{
    public class FixAdminAccountModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<FixAdminAccountModel> _logger;

        public FixAdminAccountModel(
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext context,
            IEncryptionService encryptionService,
            ILogger<FixAdminAccountModel> logger)
        {
            _userManager = userManager;
            _context = context;
            _encryptionService = encryptionService;
            _logger = logger;
        }

        public ApplicationUser AdminAccount { get; set; }
        public string SuccessMessage { get; set; }
        public string ErrorMessage { get; set; }
        public int CurrentShiftValue { get; set; }
        public string CorrectEmail { get; set; } = "admin@example.com";
        public string CorrectUsername { get; set; } = "admin";
        public string EncryptedEmail { get; set; }
        public string DecryptedEmail { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            try
            {
                // Get the current shift value
                CurrentShiftValue = _encryptionService.GetShiftValue();

                // Find admin accounts
                var adminUsers = await _userManager.GetUsersInRoleAsync("Admin");
                AdminAccount = adminUsers.FirstOrDefault(u => u.IsAdmin);

                if (AdminAccount != null)
                {
                    // Try to decrypt the email
                    try
                    {
                        DecryptedEmail = _encryptionService.Decrypt(AdminAccount.Email);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error decrypting admin email");
                        DecryptedEmail = "Error decrypting";
                    }

                    // Encrypt the correct email with current shift value
                    EncryptedEmail = _encryptionService.Encrypt(CorrectEmail);
                }
                else
                {
                    ErrorMessage = "No admin account found";
                }

                return Page();
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error: {ex.Message}";
                return Page();
            }
        }

        public async Task<IActionResult> OnPostAsync(string correctEmail, string correctUsername)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(correctEmail) || string.IsNullOrWhiteSpace(correctUsername))
                {
                    ErrorMessage = "Email and username are required";
                    return await OnGetAsync();
                }

                // Get admin account
                var adminUsers = await _userManager.GetUsersInRoleAsync("Admin");
                var adminAccount = adminUsers.FirstOrDefault(u => u.IsAdmin);

                if (adminAccount == null)
                {
                    ErrorMessage = "No admin account found";
                    return await OnGetAsync();
                }

                // Get current shift value
                CurrentShiftValue = _encryptionService.GetShiftValue();

                // Encrypt the correct values with current shift value
                string encryptedEmail = _encryptionService.Encrypt(correctEmail);
                string encryptedUsername = _encryptionService.Encrypt(correctUsername);

                // Update the admin account
                adminAccount.Email = encryptedEmail;
                adminAccount.NormalizedEmail = encryptedEmail.ToUpper();
                adminAccount.UserName = encryptedUsername;
                adminAccount.NormalizedUserName = encryptedUsername.ToUpper();

                // Save changes
                var result = await _userManager.UpdateAsync(adminAccount);

                if (result.Succeeded)
                {
                    SuccessMessage = $"Admin account updated successfully. Email is now correctly encrypted as '{encryptedEmail}'";
                }
                else
                {
                    ErrorMessage = "Failed to update admin account: " + string.Join(", ", result.Errors.Select(e => e.Description));
                }

                return await OnGetAsync();
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error: {ex.Message}";
                return await OnGetAsync();
            }
        }
    }
} 