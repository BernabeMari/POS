using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.ComponentModel.DataAnnotations;

namespace POS.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEncryptionService _encryptionService;

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<RegisterModel> logger,
            IEncryptionService encryptionService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _logger = logger;
            _encryptionService = encryptionService;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }
        
        // Flag to indicate if this is a post-back after validation errors
        [TempData]
        public bool HasValidationErrors { get; set; }

        public class InputModel
        {
            private string _fullName;
            [Required]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 3)]
            [Display(Name = "Full Name")]
            public string FullName 
            { 
                get => _fullName;
                set => _fullName = SqlInputSanitizer.SanitizeString(value);
            }
            
            private string _userName;
            [Required]
            [StringLength(50, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 3)]
            [Display(Name = "Username")]
            public string UserName
            {
                get => _userName;
                set => _userName = SqlInputSanitizer.SanitizeString(value);
            }

            private string _email;
            [Required]
            [EmailAddress]
            [Display(Name = "Email")]
            public string Email
            {
                get => _email;
                set => _email = SqlInputSanitizer.SanitizeEmail(value);
            }

            [Required]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
            
            [Display(Name = "Senior Citizen or PWD")]
            public bool IsSeniorOrPWD { get; set; }
            
            private string _seniorPwdType;
            [Display(Name = "Type")]
            public string SeniorPwdType
            {
                get => _seniorPwdType;
                set => _seniorPwdType = SqlInputSanitizer.SanitizeString(value);
            }
            
            [Required]
            [Display(Name = "I agree to the Terms and Conditions")]
            [Range(typeof(bool), "true", "true", ErrorMessage = "You must agree to the terms and conditions")]
            public bool AgreeToTerms { get; set; }
        }

        public void OnGet(string returnUrl = null)
        {
            ReturnUrl = returnUrl;
            // Initialize empty Input model with defaults
            Input = new InputModel
            {
                IsSeniorOrPWD = false,
                SeniorPwdType = null,  // Explicitly set to null to avoid validation errors
                AgreeToTerms = false
            };
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            
            // Clear validation errors for Type if IsSeniorOrPWD is false
            if (!Input.IsSeniorOrPWD)
            {
                ModelState.Remove("Input.SeniorPwdType");
                Input.SeniorPwdType = null; // Ensure it's null for non-senior/PWD users
            }
            else if (Input.IsSeniorOrPWD && string.IsNullOrEmpty(Input.SeniorPwdType))
            {
                ModelState.AddModelError(string.Empty, "You must verify your Senior Citizen or PWD status through QR code scanning.");
            }
            
            if (ModelState.IsValid)
            {
                // Encrypt sensitive information
                string encryptedFullName = _encryptionService.Encrypt(Input.FullName);
                string encryptedEmail = _encryptionService.Encrypt(Input.Email);
                string encryptedUserName = _encryptionService.Encrypt(Input.Email);
                
                var user = new ApplicationUser
                {
                    UserName = encryptedUserName,
                    NormalizedUserName = encryptedUserName.ToUpper(),
                    Email = encryptedEmail,
                    NormalizedEmail = encryptedEmail.ToUpper(),
                    FullName = encryptedFullName,
                    EmailConfirmed = true,
                    IsSeniorCitizen = Input.IsSeniorOrPWD && Input.SeniorPwdType == "Senior",
                    IsPWD = Input.IsSeniorOrPWD && Input.SeniorPwdType == "PWD"
                };
                
                var result = await _userManager.CreateAsync(user, Input.Password);
                
                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");
                    _logger.LogInformation($"Senior/PWD Status: {(user.IsSeniorCitizen ? "Senior Citizen" : user.IsPWD ? "PWD" : "None")}");

                    // Ensure Admin role exists
                    if (!await _roleManager.RoleExistsAsync("Admin"))
                    {
                        await _roleManager.CreateAsync(new IdentityRole("Admin"));
                    }

                    // Ensure User role exists
                    if (!await _roleManager.RoleExistsAsync("User"))
                    {
                        await _roleManager.CreateAsync(new IdentityRole("User"));
                    }

                    // Add user to User role
                    await _userManager.AddToRoleAsync(user, "User");

                    // Store original username and temporarily set it to decrypted version for sign-in
                    var originalUsername = user.UserName;
                    try
                    {
                        // Use decrypted username for sign-in to ensure proper claims
                        user.UserName = Input.Email; // Use email as username
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        
                        // Restore original encrypted username in the user object 
                        // (this doesn't affect the already created claims)
                        user.UserName = originalUsername;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error during sign-in with decrypted username after registration");
                        // Restore original username and fall back to normal sign-in
                        user.UserName = originalUsername;
                        await _signInManager.SignInAsync(user, isPersistent: false);
                    }
                    
                    return LocalRedirect("/User/Index");
                }
                
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            // If we got this far, something failed, redisplay form
            HasValidationErrors = true;
            // The Input model already contains the submitted values because of [BindProperty]
            return Page();
        }
    }
} 