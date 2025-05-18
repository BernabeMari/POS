using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Services;

namespace POS.Pages.Admin
{
    public class EncryptionSettingsModel : PageModel
    {
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<EncryptionSettingsModel> _logger;

        public EncryptionSettingsModel(
            IEncryptionService encryptionService,
            ILogger<EncryptionSettingsModel> logger)
        {
            _encryptionService = encryptionService;
            _logger = logger;
        }

        public int CurrentShiftValue { get; set; }
        public string SuccessMessage { get; set; }
        public string ErrorMessage { get; set; }
        
        // For encryption testing
        [BindProperty]
        public string TextToEncrypt { get; set; } = "admin@example.com";
        public string EncryptedText { get; set; }
        public string DecryptedText { get; set; }

        public void OnGet()
        {
            CurrentShiftValue = _encryptionService.GetShiftValue();
        }

        public IActionResult OnPost(int newShiftValue)
        {
            try
            {
                _logger.LogInformation($"Updating shift value from {_encryptionService.GetShiftValue()} to {newShiftValue}");
                
                // Validate input
                if (newShiftValue < 1 || newShiftValue > 25)
                {
                    ErrorMessage = "Shift value must be between 1 and 25";
                    CurrentShiftValue = _encryptionService.GetShiftValue();
                    return Page();
                }
                
                // Current shift value
                CurrentShiftValue = _encryptionService.GetShiftValue();
                
                // If shift value hasn't changed, don't do anything
                if (newShiftValue == CurrentShiftValue)
                {
                    SuccessMessage = "No changes made - the new shift value is the same as the current one";
                    return Page();
                }
                
                // Update shift value - this will also re-encrypt all data
                bool success = _encryptionService.UpdateShiftValue(newShiftValue, User.Identity.Name);
                
                if (success)
                {
                    SuccessMessage = $"Shift value updated to {newShiftValue} and all user data re-encrypted successfully";
                    CurrentShiftValue = newShiftValue;
                }
                else
                {
                    ErrorMessage = "Failed to update shift value";
                    CurrentShiftValue = _encryptionService.GetShiftValue();
                }
                
                return Page();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating shift value");
                ErrorMessage = $"Error: {ex.Message}";
                CurrentShiftValue = _encryptionService.GetShiftValue();
                return Page();
            }
        }
        
        public IActionResult OnPostTestEncryption(string textToEncrypt)
        {
            CurrentShiftValue = _encryptionService.GetShiftValue();
            TextToEncrypt = textToEncrypt;
            
            try
            {
                // Encrypt the text
                EncryptedText = _encryptionService.Encrypt(textToEncrypt);
                
                // Test decryption to verify
                DecryptedText = _encryptionService.Decrypt(EncryptedText);
                
                return Page();
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error testing encryption: {ex.Message}";
                return Page();
            }
        }
    }
} 