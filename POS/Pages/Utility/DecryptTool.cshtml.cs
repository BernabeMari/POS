using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Services;

namespace POS.Pages.Utility
{
    public class DecryptToolModel : PageModel
    {
        private readonly IEncryptionService _encryptionService;

        public DecryptToolModel(IEncryptionService encryptionService)
        {
            _encryptionService = encryptionService;
        }

        [BindProperty]
        public string EncryptedValue { get; set; }

        public string DecryptedValue { get; set; }

        public string ErrorMessage { get; set; }

        public void OnGet()
        {
            // Initialize page
        }

        public IActionResult OnPost()
        {
            if (string.IsNullOrEmpty(EncryptedValue))
            {
                ErrorMessage = "Please enter an encrypted value.";
                return Page();
            }

            try
            {
                // Try to decrypt the value
                DecryptedValue = _encryptionService.Decrypt(EncryptedValue);
            }
            catch (Exception ex)
            {
                // Handle decryption error
                ErrorMessage = $"Error decrypting value: {ex.Message}";
                
                // Check if the input is a valid Base64 string
                try
                {
                    Convert.FromBase64String(EncryptedValue);
                }
                catch
                {
                    ErrorMessage += " The input is not a valid Base64 string.";
                }
            }

            return Page();
        }
    }
} 