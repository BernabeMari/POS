using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using System.ComponentModel.DataAnnotations;

namespace POS.Areas.Admin.Pages
{
    public class UserManagementModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _context;

        public UserManagementModel(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ApplicationDbContext context)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
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
            CurrentFilter = filter;
            
            // Load all active positions for dropdowns
            await LoadPositionOptions();

            // Get all users with their positions
            var usersQuery = _userManager.Users
                .Include(u => u.Position)
                .AsQueryable();

            // Apply filter
            switch (filter.ToLower())
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
            
            // Build the view model with roles
            Users = new List<UserViewModel>();
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                
                Users.Add(new UserViewModel
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    FullName = user.FullName,
                    IsAdmin = user.IsAdmin,
                    IsEmployee = user.IsEmployee,
                    PositionId = user.PositionId,
                    Position = user.Position,
                    CreatedAt = user.CreatedAt,
                    Roles = roles.ToList()
                });
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Validate form
            if (!ModelState.IsValid)
            {
                await LoadPositionOptions();
                await OnGetAsync();
                return Page();
            }

            // Validate password
            if (NewUser.Password != NewUser.ConfirmPassword)
            {
                ModelState.AddModelError("NewUser.ConfirmPassword", "The password and confirmation password do not match.");
                await LoadPositionOptions();
                await OnGetAsync();
                return Page();
            }

            // Create new user
            var user = new ApplicationUser
            {
                UserName = NewUser.UserName,
                Email = NewUser.Email,
                FullName = NewUser.FullName,
                IsAdmin = NewUser.IsAdmin,
                IsEmployee = NewUser.IsEmployee,
                PositionId = NewUser.IsEmployee ? NewUser.PositionId : null,
                CreatedAt = DateTime.Now
            };

            try
            {
                var result = await _userManager.CreateAsync(user, NewUser.Password);

                if (result.Succeeded)
                {
                    // Assign roles based on user type
                    if (NewUser.IsAdmin)
                    {
                        await _userManager.AddToRoleAsync(user, "Admin");
                    }
                    
                    if (NewUser.IsEmployee)
                    {
                        await _userManager.AddToRoleAsync(user, "Employee");
                    }
                    else
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                    }

                    SuccessMessage = $"User '{user.UserName}' has been created successfully.";
                    return RedirectToPage();
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error creating user: {ex.Message}";
            }

            await LoadPositionOptions();
            await OnGetAsync();
            return Page();
        }

        public async Task<IActionResult> OnPostEditAsync(string id, string fullName, string email, 
            string password, bool isAdmin, bool isEmployee, int? positionId)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                ErrorMessage = "User not found.";
                return RedirectToPage();
            }

            try
            {
                // Update basic info
                user.FullName = fullName;
                user.Email = email;
                
                // Update role flags
                bool wasAdmin = user.IsAdmin;
                bool wasEmployee = user.IsEmployee;
                
                user.IsAdmin = isAdmin;
                user.IsEmployee = isEmployee;
                
                // Update position if employee
                if (isEmployee)
                {
                    user.PositionId = positionId;
                }
                else
                {
                    user.PositionId = null;
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
                            ModelState.AddModelError(string.Empty, error.Description);
                        }
                        
                        await LoadPositionOptions();
                        await OnGetAsync();
                        return Page();
                    }
                }

                // Save user changes
                var result = await _userManager.UpdateAsync(user);
                
                if (result.Succeeded)
                {
                    // Update roles
                    if (isAdmin && !wasAdmin)
                    {
                        await _userManager.AddToRoleAsync(user, "Admin");
                    }
                    else if (!isAdmin && wasAdmin)
                    {
                        await _userManager.RemoveFromRoleAsync(user, "Admin");
                    }
                    
                    if (isEmployee && !wasEmployee)
                    {
                        await _userManager.AddToRoleAsync(user, "Employee");
                        await _userManager.RemoveFromRoleAsync(user, "User");
                    }
                    else if (!isEmployee && wasEmployee)
                    {
                        await _userManager.RemoveFromRoleAsync(user, "Employee");
                        await _userManager.AddToRoleAsync(user, "User");
                    }
                    
                    SuccessMessage = $"User '{user.UserName}' has been updated successfully.";
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    
                    await LoadPositionOptions();
                    await OnGetAsync();
                    return Page();
                }
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error updating user: {ex.Message}";
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDeleteAsync(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                ErrorMessage = "User not found.";
                return RedirectToPage();
            }

            try
            {
                var result = await _userManager.DeleteAsync(user);
                if (result.Succeeded)
                {
                    SuccessMessage = $"User '{user.UserName}' has been deleted successfully.";
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    
                    await LoadPositionOptions();
                    await OnGetAsync();
                    return Page();
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
        public bool IsAdmin { get; set; }
        public bool IsEmployee { get; set; }
        public int? PositionId { get; set; }
        public Position? Position { get; set; }
        public DateTime CreatedAt { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
    }

    public class NewUserViewModel
    {
        [Required]
        [Display(Name = "Full Name")]
        public string FullName { get; set; }

        [Required]
        [Display(Name = "Username")]
        public string UserName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        [Display(Name = "Is Admin")]
        public bool IsAdmin { get; set; }

        [Display(Name = "Is Employee")]
        public bool IsEmployee { get; set; }

        [Display(Name = "Position")]
        public int? PositionId { get; set; }
    }
} 