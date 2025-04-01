using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.ComponentModel.DataAnnotations;

namespace POS.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILoginAttemptService _loginAttemptService;

        public LoginModel(
            SignInManager<ApplicationUser> signInManager, 
            UserManager<ApplicationUser> userManager,
            ILoginAttemptService loginAttemptService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _loginAttemptService = loginAttemptService;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

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
                // Find user by email
                var user = await _userManager.FindByEmailAsync(Input.Email);
                
                if (user != null)
                {
                    // Check if user is locked out by our custom mechanism
                    bool isLockedOut = await _loginAttemptService.IsUserLockedOutAsync(user.Email);
                    if (isLockedOut)
                    {
                        // Store the username in TempData for the lockout page
                        TempData["LockedOutUser"] = user.Email;
                        return RedirectToPage("./Lockout");
                    }

                    // Attempt to sign in with password (don't use lockoutOnFailure as we're handling it ourselves)
                    var result = await _signInManager.PasswordSignInAsync(user.UserName, Input.Password, Input.RememberMe, lockoutOnFailure: false);
                    
                    if (result.Succeeded)
                    {
                        // Reset any failed attempts on successful login
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
                    
                    if (result.RequiresTwoFactor)
                    {
                        return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                    }
                    
                    if (result.IsLockedOut)
                    {
                        return RedirectToPage("./Lockout");
                    }
                    
                    // Record failed attempt
                    var (nowLockedOut, timeRemaining) = await _loginAttemptService.RecordFailedAttemptAsync(user.Email);
                    
                    if (nowLockedOut)
                    {
                        // Store the username in TempData for the lockout page
                        TempData["LockedOutUser"] = user.Email;
                        
                        // User just got locked out after this attempt
                        return RedirectToPage("./Lockout");
                    }
                    
                    // Get the login settings to display appropriate message
                    var settings = await _loginAttemptService.GetLoginSettingsAsync();
                    var attemptInfo = _loginAttemptService.GetAttemptInfo(user.Email);
                    int remainingAttempts = settings.MaxLoginAttempts - attemptInfo.attempts;
                    
                    if (remainingAttempts > 0)
                    {
                        // Add error to ModelState's general errors collection (empty key)
                        ModelState.AddModelError(string.Empty, $"Invalid email or password. You have {remainingAttempts} login {(remainingAttempts == 1 ? "attempt" : "attempts")} remaining before your account is temporarily locked.");
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid login attempt. Your account has been temporarily locked.");
                        
                        // This should not normally happen, but just in case the account should be locked
                        TempData["LockedOutUser"] = user.Email;
                        return RedirectToPage("./Lockout");
                    }
                }
                else
                {
                    // User not found - be vague about the error to avoid username enumeration
                    ModelState.AddModelError(string.Empty, "Invalid email or password.");
                }
                
                return Page();
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }
    }
} 