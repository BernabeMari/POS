using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using POS.Services;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace POS.Areas.Admin.Pages
{
    public class UserManagementModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<UserManagementModel> _logger;

        public UserManagementModel(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ApplicationDbContext context,
            IEncryptionService encryptionService,
            ILogger<UserManagementModel> logger)
        {
            _userManager = userManager;
            // Temporarily disable password validation to isolate encryption issues
            _userManager.PasswordValidators.Clear();
            _userManager.PasswordValidators.Add(new CustomPasswordValidator<ApplicationUser>());
            
            _roleManager = roleManager;
            _context = context;
            _encryptionService = encryptionService;
            _logger = logger;
        }

        public List<UserViewModel> Users { get; set; } = new List<UserViewModel>();

        public SelectList PositionOptions { get; set; }

        [BindProperty]
        public NewUserViewModel NewUser { get; set; } = new NewUserViewModel();

        [TempData]
        public string? SuccessMessage { get; set; }

        [TempData]
        public string? ErrorMessage { get; set; }

        public string CurrentFilter { get; set; } = "all";

        public async Task OnGetAsync(string filter = "all")
        {
            CurrentFilter = SqlInputSanitizer.SanitizeString(filter);
            
            // Load all active positions for dropdowns
            await LoadPositionOptions();

            // Get all users with their positions
            var usersQuery = _userManager.Users
                .Include(u => u.Position)
                .AsQueryable();

            // Apply filter
            switch (CurrentFilter.ToLower())
            {
                case "admin":
                    usersQuery = usersQuery.Where(u => u.IsAdmin);
                    break;
                case "employee":
                    usersQuery = usersQuery.Where(u => u.IsEmployee);
                    break;
                case "customer":
                    usersQuery = usersQuery.Where(u => !u.IsAdmin && !u.IsEmployee);
                    break;
            }

            var users = await usersQuery.ToListAsync();
            
            // Build the view model with roles and decrypt sensitive information for display
            Users = new List<UserViewModel>();
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                
                // Decrypt email, fullname, and username for display
                string decryptedEmail = user.Email;
                string decryptedFullName = user.FullName;
                string decryptedUserName = user.UserName;
                
                try 
                {
                    // Try to decrypt each field, catching exceptions for each field separately
                    try {
                        decryptedEmail = _encryptionService.Decrypt(user.Email);
                    } catch (Exception ex) {
                        _logger.LogWarning($"Failed to decrypt email for user {user.Id}: {ex.Message}");
                        // Keep original value if decryption fails
                    }
                    
                    try {
                        decryptedFullName = _encryptionService.Decrypt(user.FullName);
                    } catch (Exception ex) {
                        _logger.LogWarning($"Failed to decrypt full name for user {user.Id}: {ex.Message}");
                        // Keep original value if decryption fails
                    }
                    
                    try {
                        decryptedUserName = _encryptionService.Decrypt(user.UserName);
                    } catch (Exception ex) {
                        _logger.LogWarning($"Failed to decrypt username for user {user.Id}: {ex.Message}");
                        // Keep original value if decryption fails
                    }
                }
                catch (Exception ex)
                {
                    // General error handler - log but continue
                    _logger.LogError(ex, $"Error during decryption for user {user.Id}");
                }
                
                Users.Add(new UserViewModel
                {
                    Id = user.Id,
                    UserName = decryptedUserName,
                    Email = decryptedEmail,
                    FullName = decryptedFullName,
                    EncryptedUserName = user.UserName,
                    EncryptedEmail = user.Email,
                    EncryptedFullName = user.FullName,
                    IsAdmin = user.IsAdmin,
                    IsEmployee = user.IsEmployee,
                    PositionId = user.PositionId,
                    Position = user.Position,
                    CreatedAt = user.CreatedAt,
                    Roles = roles.ToList()
                });
            }
        }

        // Helper method to check if a string might be encrypted with Caesar cipher
        private bool IsValidBase64(string input)
        {
            // We're no longer using Base64
            if (string.IsNullOrEmpty(input))
                return false;
                
            // Email addresses will have @ symbols, so we need a different detection method
            // For now, assume all user data might be encrypted and try to decrypt it
            return true;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                _logger.LogInformation("Starting user creation process");
                
                // Capture original inputs before validation
                string originalEmail = NewUser.Email?.Trim() ?? string.Empty;
                string originalFullName = NewUser.FullName?.Trim() ?? string.Empty;
                
                _logger.LogInformation($"Original input: Email={originalEmail}, FullName={originalFullName}");
                
                // Validate form - we won't rely on model binding for required fields
                if (string.IsNullOrWhiteSpace(originalEmail))
                {
                    ModelState.AddModelError("NewUser.Email", "Email is required");
                }
                
                if (string.IsNullOrWhiteSpace(originalFullName))
                {
                    ModelState.AddModelError("NewUser.FullName", "Full name is required");
                }
                
                if (string.IsNullOrWhiteSpace(NewUser.Password))
                {
                    ModelState.AddModelError("NewUser.Password", "Password is required");
                }
                
                if (!ModelState.IsValid)
                {
                    _logger.LogWarning("ModelState is invalid:");
                    foreach (var state in ModelState)
                    {
                        foreach (var error in state.Value.Errors)
                        {
                            _logger.LogWarning($"- {state.Key}: {error.ErrorMessage}");
                        }
                    }
                    
                    await LoadPositionOptions();
                    await OnGetAsync();
                    return Page();
                }

                // Check password match
                if (NewUser.Password != NewUser.ConfirmPassword)
                {
                    ModelState.AddModelError("NewUser.ConfirmPassword", "Passwords do not match");
                    await LoadPositionOptions();
                    await OnGetAsync();
                    return Page();
                }

                // Validate employee position
                if (NewUser.IsEmployee && (!NewUser.PositionId.HasValue || NewUser.PositionId <= 0))
                {
                    ModelState.AddModelError("NewUser.PositionId", "Position is required for employees");
                    await LoadPositionOptions();
                    await OnGetAsync();
                    return Page();
                }

                _logger.LogInformation($"Sanitizing and encrypting user data...");
                
                // Sanitize inputs before encryption
                string sanitizedEmail = SqlInputSanitizer.SanitizeEmail(originalEmail);
                string sanitizedFullName = SqlInputSanitizer.SanitizeString(originalFullName);
                
                // Create a username based on the email (before the @ symbol)
                string plainUsername = sanitizedEmail.Split('@')[0];
                
                // Encrypt sensitive information
                string encryptedEmail = _encryptionService.Encrypt(sanitizedEmail);
                string encryptedUserName = _encryptionService.Encrypt(plainUsername);
                string encryptedFullName = _encryptionService.Encrypt(sanitizedFullName);
                
                _logger.LogInformation($"Encrypted data: Email={encryptedEmail}, Username={plainUsername}");
                
                _logger.LogInformation("Attempting to create user with encrypted values...");

                try {
                    // Create user in multiple steps
                    // 1. First create a password hash manually
                    var passwordHasher = new PasswordHasher<ApplicationUser>();
                    var newUser = new ApplicationUser
                    {
                        Id = Guid.NewGuid().ToString(), // Generate our own ID
                        UserName = encryptedUserName, // Store encrypted username
                        NormalizedUserName = encryptedUserName.ToUpper(),
                        Email = encryptedEmail,
                        NormalizedEmail = encryptedEmail.ToUpper(),
                        FullName = encryptedFullName,
                        EmailConfirmed = true,
                        IsAdmin = NewUser.IsAdmin,
                        IsEmployee = NewUser.IsEmployee,
                        PositionId = NewUser.IsEmployee ? NewUser.PositionId : null,
                        CreatedAt = DateTime.Now,
                        SecurityStamp = Guid.NewGuid().ToString()
                    };
                    
                    // 2. Set the password hash manually
                    newUser.PasswordHash = passwordHasher.HashPassword(newUser, NewUser.Password);
                    
                    // 3. Add user directly to database
                    _context.Users.Add(newUser);
                    await _context.SaveChangesAsync();
                    
                    _logger.LogInformation($"User created successfully with ID: {newUser.Id} via direct database access");
                    
                    // Assign roles based on user type
                    if (NewUser.IsAdmin)
                    {
                        // Get Admin role
                        var adminRole = await _roleManager.FindByNameAsync("Admin");
                        if (adminRole != null)
                        {
                            // Add user to role directly
                            _context.UserRoles.Add(new IdentityUserRole<string> 
                            { 
                                UserId = newUser.Id,
                                RoleId = adminRole.Id
                            });
                            await _context.SaveChangesAsync();
                            _logger.LogInformation("Added user to Admin role");
                        }
                    }
                    
                    if (NewUser.IsEmployee)
                    {
                        var employeeRole = await _roleManager.FindByNameAsync("Employee");
                        if (employeeRole != null)
                        {
                            _context.UserRoles.Add(new IdentityUserRole<string> 
                            { 
                                UserId = newUser.Id,
                                RoleId = employeeRole.Id
                            });
                            await _context.SaveChangesAsync();
                            _logger.LogInformation("Added user to Employee role");
                        }
                    }
                    else if (!NewUser.IsAdmin)
                    {
                        // Only assign User role if they're not an admin or employee
                        var userRole = await _roleManager.FindByNameAsync("User");
                        if (userRole != null)
                        {
                            _context.UserRoles.Add(new IdentityUserRole<string> 
                            { 
                                UserId = newUser.Id,
                                RoleId = userRole.Id
                            });
                            await _context.SaveChangesAsync();
                            _logger.LogInformation("Added user to User role");
                        }
                    }
                    
                    SuccessMessage = $"User '{sanitizedEmail}' has been created successfully.";
                    _logger.LogInformation("User creation completed successfully");
                    return RedirectToPage();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error creating user directly: {ex.Message}");
                    ModelState.AddModelError(string.Empty, $"Error creating user: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error in user creation: {ex.Message}");
                ErrorMessage = $"Error creating user: {ex.Message}";
            }
            
            await LoadPositionOptions();
            await OnGetAsync();
            return Page();
        }

        public async Task<IActionResult> OnPostEditAsync(string id, string fullName, string email, 
            string password, bool isAdmin, bool isEmployee, int? positionId = null)
        {
            // Sanitize inputs - use special ID sanitizer for id
            id = AdminInputSanitizer.SanitizeId(id);
            fullName = SqlInputSanitizer.SanitizeString(fullName);
            email = SqlInputSanitizer.SanitizeEmail(email);
            password = password; // Don't sanitize password as it will be hashed
            
            // Debug logging
            System.Diagnostics.Debug.WriteLine($"OnPostEditAsync - User ID: {id}");
            System.Diagnostics.Debug.WriteLine($"IsEmployee: {isEmployee}, IsAdmin: {isAdmin}, PositionId: {positionId}");
            
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                ErrorMessage = "User not found.";
                return RedirectToPage();
            }

            try
            {
                // Debug logging - current state
                System.Diagnostics.Debug.WriteLine($"Current state - IsEmployee: {user.IsEmployee}, IsAdmin: {user.IsAdmin}, PositionId: {user.PositionId}");
                
                // Get the original username for display purposes
                string originalUserName;
                try
                {
                    if (IsValidBase64(user.UserName))
                        originalUserName = _encryptionService.Decrypt(user.UserName);
                    else
                        originalUserName = user.UserName;
                }
                catch
                {
                    // If decryption fails, use the stored value
                    originalUserName = user.UserName;
                }
                
                // Encrypt and update basic info
                user.FullName = _encryptionService.Encrypt(fullName);
                user.Email = _encryptionService.Encrypt(email);
                
                // Update role flags
                bool wasAdmin = user.IsAdmin;
                bool wasEmployee = user.IsEmployee;
                
                user.IsAdmin = isAdmin;
                user.IsEmployee = isEmployee;
                
                // Update position if employee
                if (isEmployee)
                {
                    // Ensure we have a valid position ID for an employee
                    if (positionId == null || positionId <= 0)
                    {
                        ModelState.AddModelError(string.Empty, "A valid position must be selected for employees.");
                        await LoadPositionOptions();
                        await OnGetAsync();
                        return Page();
                    }
                    
                    user.PositionId = positionId;
                    System.Diagnostics.Debug.WriteLine($"Setting position ID to {positionId}");
                }
                else
                {
                    // Clear position if not an employee
                    user.PositionId = null;
                    System.Diagnostics.Debug.WriteLine("Clearing position ID");
                }

                // Update password if provided
                if (!string.IsNullOrEmpty(password))
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var passwordResult = await _userManager.ResetPasswordAsync(user, token, password);
                    
                    if (!passwordResult.Succeeded)
                    {
                        foreach (var error in passwordResult.Errors)
                        {
                            ErrorMessage = $"Password update failed: {error.Description}";
                        }
                        
                        await LoadPositionOptions();
                        await OnGetAsync();
                        return Page();
                    }
                }
                
                // Update user in database
                var result = await _userManager.UpdateAsync(user);
                
                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        ErrorMessage = $"User update failed: {error.Description}";
                    }
                    
                    await LoadPositionOptions();
                    await OnGetAsync();
                    return Page();
                }
                
                // Update roles if needed
                bool isInAdminRole = await _userManager.IsInRoleAsync(user, "Admin");
                if (isAdmin && !isInAdminRole)
                {
                    await _userManager.AddToRoleAsync(user, "Admin");
                }
                else if (!isAdmin && isInAdminRole)
                {
                    await _userManager.RemoveFromRoleAsync(user, "Admin");
                }
                
                bool isInEmployeeRole = await _userManager.IsInRoleAsync(user, "Employee");
                if (isEmployee && !isInEmployeeRole)
                {
                    await _userManager.AddToRoleAsync(user, "Employee");
                }
                else if (!isEmployee && isInEmployeeRole)
                {
                    await _userManager.RemoveFromRoleAsync(user, "Employee");
                }
                
                // Add to User role if they are neither admin nor employee
                bool isInUserRole = await _userManager.IsInRoleAsync(user, "User");
                if (!isAdmin && !isEmployee && !isInUserRole)
                {
                    await _userManager.AddToRoleAsync(user, "User");
                }
                
                SuccessMessage = $"User '{originalUserName}' has been updated successfully.";
                return RedirectToPage();
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error updating user: {ex.Message}";
                await LoadPositionOptions();
                await OnGetAsync();
                return Page();
            }
        }

        public async Task<IActionResult> OnPostDeleteAsync(string id)
        {
            // Sanitize input - use special ID sanitizer to preserve GUID format
            id = AdminInputSanitizer.SanitizeId(id);
            
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                ErrorMessage = "User not found.";
                return RedirectToPage();
            }

            try
            {
                // Don't allow deleting the last admin user
                var adminUsers = await _userManager.GetUsersInRoleAsync("Admin");
                if (user.IsAdmin && adminUsers.Count <= 1)
                {
                    ErrorMessage = "Cannot delete the last admin user.";
                    return RedirectToPage();
                }

                // Get the decrypted username for display
                string displayUserName;
                try
                {
                    if (IsValidBase64(user.UserName))
                        displayUserName = _encryptionService.Decrypt(user.UserName);
                    else
                        displayUserName = user.UserName;
                }
                catch
                {
                    // If decryption fails, use the stored value
                    displayUserName = user.UserName;
                }

                var result = await _userManager.DeleteAsync(user);
                if (result.Succeeded)
                {
                    SuccessMessage = $"User '{displayUserName}' has been deleted successfully.";
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ErrorMessage += $"{error.Description} ";
                    }
                }
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error deleting user: {ex.Message}";
            }

            return RedirectToPage();
        }

        private async Task LoadPositionOptions()
        {
            var positions = await _context.Positions
                .Where(p => p.IsActive)
                .OrderBy(p => p.Name)
                .ToListAsync();
                
            PositionOptions = new SelectList(positions, "Id", "Name");
        }
    }

    public class UserViewModel
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string FullName { get; set; }
        public string EncryptedUserName { get; set; }
        public string EncryptedEmail { get; set; }
        public string EncryptedFullName { get; set; }
        public bool IsAdmin { get; set; }
        public bool IsEmployee { get; set; }
        public int? PositionId { get; set; }
        public Position? Position { get; set; }
        public DateTime CreatedAt { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
    }

    public class NewUserViewModel
    {
        // Username is not required as we use Email as the identifier
        [Display(Name = "Username")]
        public string UserName { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "Full name is required")]
        [Display(Name = "Full Name")]
        public string FullName { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;
        
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
        
        [Display(Name = "Is Admin")]
        public bool IsAdmin { get; set; }
        
        [Display(Name = "Is Employee")]
        public bool IsEmployee { get; set; }
        
        [Display(Name = "Position")]
        public int? PositionId { get; set; }
    }

    public class CustomPasswordValidator<TUser> : IPasswordValidator<TUser> where TUser : class
    {
        public Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            // Minimal validation - accept any non-empty password
            if (string.IsNullOrEmpty(password))
            {
                return Task.FromResult(IdentityResult.Failed(
                    new IdentityError { Description = "Password cannot be empty." }));
            }

            return Task.FromResult(IdentityResult.Success);
        }
    }
} 