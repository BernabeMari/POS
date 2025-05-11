using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using Microsoft.Extensions.Logging;

namespace POS.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILoginAttemptService _loginAttemptService;
        private readonly IEncryptionService _encryptionService;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(
            SignInManager<ApplicationUser> signInManager, 
            UserManager<ApplicationUser> userManager,
            ILoginAttemptService loginAttemptService,
            IEncryptionService encryptionService,
            ApplicationDbContext context,
            ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _loginAttemptService = loginAttemptService;
            _encryptionService = encryptionService;
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            private string _email;
            [Required]
            [EmailAddress]
            public string Email
            {
                get => _email;
                set => _email = SqlInputSanitizer.SanitizeEmail(value);
            }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            if (ModelState.IsValid)
            {
                _logger.LogInformation($"Attempting login for email: {Input.Email}");
                
                // Since email is encrypted in the database, we need a different approach to find the user
                string encryptedEmail = _encryptionService.Encrypt(Input.Email);
                _logger.LogDebug($"Encrypted email for search: {encryptedEmail}");
                
                // Try to find user by encrypted email
                var user = await _context.Users.FirstOrDefaultAsync(u => 
                    u.Email == encryptedEmail || 
                    u.NormalizedEmail == encryptedEmail.ToUpper() ||
                    u.Email == Input.Email || 
                    u.NormalizedEmail == Input.Email.ToUpper());
                
                if (user == null)
                {
                    _logger.LogDebug("User not found by direct lookup, trying decryption approach");
                    
                    // If direct match failed, try to find by iterating and decrypting (less efficient but necessary)
                    var allUsers = await _context.Users.ToListAsync();
                    _logger.LogDebug($"Searching through {allUsers.Count} users");
                    
                    foreach (var potentialUser in allUsers)
                    {
                        try
                        {
                            _logger.LogDebug($"Checking user ID: {potentialUser.Id}, Email: {potentialUser.Email}, UserName: {potentialUser.UserName}");
                            
                            // Check if email is valid Base64 and try to decrypt
                            if (IsValidBase64(potentialUser.Email))
                            {
                                string decryptedEmail = _encryptionService.Decrypt(potentialUser.Email);
                                _logger.LogDebug($"Decrypted email: {decryptedEmail}");
                                
                                if (decryptedEmail.Equals(Input.Email, StringComparison.OrdinalIgnoreCase))
                                {
                                    _logger.LogInformation($"Found user by decrypted email: {potentialUser.Id}");
                                    user = potentialUser;
                                    break;
                                }
                            }
                            // For legacy users with unencrypted emails
                            else if (potentialUser.Email.Equals(Input.Email, StringComparison.OrdinalIgnoreCase))
                            {
                                _logger.LogInformation($"Found user by legacy (unencrypted) email: {potentialUser.Id}");
                                user = potentialUser;
                                break;
                            }
                        }
                        catch (Exception ex) 
                        { 
                            _logger.LogError(ex, $"Error during email decryption for user {potentialUser.Id}");
                        }
                    }
                }
                else
                {
                    _logger.LogInformation($"Found user directly: {user.Id}");
                }
                
                if (user != null)
                {
                    // Check if user is locked out by our custom mechanism
                    bool userIsLockedOut = await _loginAttemptService.IsUserLockedOutAsync(user.Email);
                    if (userIsLockedOut)
                    {
                        // Store the username in TempData for the lockout page
                        TempData["LockedOutUser"] = user.Email;
                        return RedirectToPage("./Lockout");
                    }

                    // Decrypt username for signin
                    string decryptedUserName;
                    try
                    {
                        _logger.LogDebug($"Attempting to decrypt username: {user.UserName}");
                        decryptedUserName = _encryptionService.Decrypt(user.UserName);
                        _logger.LogDebug($"Successfully decrypted username to: {decryptedUserName}");
                    }
                    catch (Exception ex)
                    {
                        // If decryption fails, use the stored username (handles legacy users)
                        _logger.LogWarning(ex, $"Failed to decrypt username, using original: {user.UserName}");
                        decryptedUserName = user.UserName;
                    }

                    // Don't use PasswordSignInAsync as it requires exact username match
                    // Instead, verify the password directly and create a manual sign-in
                    var passwordCorrect = await _userManager.CheckPasswordAsync(user, Input.Password);
                    if (passwordCorrect)
                    {
                        _logger.LogInformation("Password verified successfully, performing manual sign-in");
                        
                        // Store the decrypted username in the user object before signing in
                        // This will ensure the decrypted name is used in claims
                        var originalUsername = user.UserName;
                        try
                        {
                            // Temporarily modify the UserName property for sign-in
                            user.UserName = decryptedUserName;
                            
                            // Create claims principal and sign in manually
                            await _signInManager.SignInAsync(user, Input.RememberMe);
                            
                            // Restore the original encrypted username in the user object
                            // (this doesn't affect the already created claims)
                            user.UserName = originalUsername;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Error during sign-in with decrypted username");
                            // Ensure the original username is restored in case of exception
                            user.UserName = originalUsername;
                            
                            // Fallback to normal sign-in
                            await _signInManager.SignInAsync(user, Input.RememberMe);
                        }
                        
                        // Reset failed login attempts
                        await _loginAttemptService.ResetFailedAttemptsAsync(user.Email);
                        
                        // Redirect based on user role
                        if (user.IsAdmin)
                        {
                            return LocalRedirect("/Admin");
                        }
                        else if (user.IsEmployee)
                        {
                            return LocalRedirect("/Employee");
                        }
                        else
                        {
                            return LocalRedirect("/User");
                        }
                    }
                    else
                    {
                        // Record failed login attempt
                        await _loginAttemptService.RecordFailedAttemptAsync(user.Email);
                        
                        // Check if we should lock out the user after this attempt
                        int remainingAttempts = await _loginAttemptService.GetRemainingAttemptsAsync(user.Email);
                        if (remainingAttempts <= 0)
                        {
                            // User should be locked out
                            TempData["LockedOutUser"] = user.Email;
                            return RedirectToPage("./Lockout");
                        }
                        
                        ModelState.AddModelError(string.Empty, $"Invalid login attempt. Remaining attempts: {remainingAttempts}");
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                }
            }

            // If we got this far, something failed, redisplay form
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