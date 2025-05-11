using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using POS.Services;

namespace POS.Pages.Utility
{
    public class FindUserModel : PageModel
    {
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;

        public FindUserModel(ApplicationDbContext context, IEncryptionService encryptionService)
        {
            _context = context;
            _encryptionService = encryptionService;
        }

        [BindProperty]
        public string EmailOrUsername { get; set; }

        public ApplicationUser UserInfo { get; set; }

        public string ErrorMessage { get; set; }

        public void OnGet()
        {
            // Initialize page
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (string.IsNullOrEmpty(EmailOrUsername))
            {
                ErrorMessage = "Please enter an email or username.";
                return Page();
            }

            try
            {
                // First, try to find by exact match
                string encryptedValue = _encryptionService.Encrypt(EmailOrUsername);
                
                var user = await _context.Users
                    .FirstOrDefaultAsync(u => u.Email == encryptedValue || 
                                            u.Email == EmailOrUsername || 
                                            u.UserName == encryptedValue || 
                                            u.UserName == EmailOrUsername ||
                                            u.NormalizedEmail == encryptedValue.ToUpper() ||
                                            u.NormalizedEmail == EmailOrUsername.ToUpper());
                                            
                if (user == null)
                {
                    // Try to find by iterating and decrypting (less efficient, but works for already encrypted values)
                    var allUsers = await _context.Users.ToListAsync();
                    foreach (var potentialUser in allUsers)
                    {
                        try
                        {
                            bool isMatch = false;
                            
                            // Check if email is valid Base64 and matches when decrypted
                            try
                            {
                                if (IsValidBase64(potentialUser.Email))
                                {
                                    string decryptedEmail = _encryptionService.Decrypt(potentialUser.Email);
                                    if (decryptedEmail.Equals(EmailOrUsername, StringComparison.OrdinalIgnoreCase))
                                    {
                                        isMatch = true;
                                    }
                                }
                            }
                            catch { /* ignore decryption errors */ }
                            
                            // Check if normalized email is valid Base64 and matches when decrypted
                            try
                            {
                                if (IsValidBase64(potentialUser.NormalizedEmail))
                                {
                                    string decryptedNormalizedEmail = _encryptionService.Decrypt(potentialUser.NormalizedEmail);
                                    if (decryptedNormalizedEmail.Equals(EmailOrUsername, StringComparison.OrdinalIgnoreCase))
                                    {
                                        isMatch = true;
                                    }
                                }
                            }
                            catch { /* ignore decryption errors */ }
                            
                            // Check if username is valid Base64 and matches when decrypted
                            try
                            {
                                if (IsValidBase64(potentialUser.UserName))
                                {
                                    string decryptedUserName = _encryptionService.Decrypt(potentialUser.UserName);
                                    if (decryptedUserName.Equals(EmailOrUsername, StringComparison.OrdinalIgnoreCase))
                                    {
                                        isMatch = true;
                                    }
                                }
                            }
                            catch { /* ignore decryption errors */ }
                            
                            if (isMatch)
                            {
                                user = potentialUser;
                                break;
                            }
                        }
                        catch { /* ignore general errors and continue */ }
                    }
                }
                
                if (user != null)
                {
                    UserInfo = user;
                }
                else
                {
                    ErrorMessage = "User not found.";
                }
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error finding user: {ex.Message}";
            }

            return Page();
        }
        
        // Helper method to check if a string is valid Base64
        private bool IsValidBase64(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;
                
            try
            {
                Convert.FromBase64String(input);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
} 