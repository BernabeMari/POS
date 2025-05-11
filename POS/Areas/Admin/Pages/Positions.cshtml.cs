using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using POS.Services;

namespace POS.Areas.Admin.Pages
{
    public class PositionsModel : PageModel
    {
        private readonly ApplicationDbContext _context;

        public PositionsModel(ApplicationDbContext context)
        {
            _context = context;
        }

        public List<Position> Positions { get; set; } = new List<Position>();

        [BindProperty]
        public Position NewPosition { get; set; } = new Position();

        [TempData]
        public string? SuccessMessage { get; set; }

        [TempData]
        public string? ErrorMessage { get; set; }

        public async Task OnGetAsync()
        {
            Positions = await _context.Positions
                .OrderByDescending(p => p.IsActive)
                .ThenBy(p => p.Name)
                .ToListAsync();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                await OnGetAsync();
                return Page();
            }

            try
            {
                // Sanitize inputs
                NewPosition.Name = SqlInputSanitizer.SanitizeString(NewPosition.Name);
                NewPosition.Description = SqlInputSanitizer.SanitizeString(NewPosition.Description);
                
                NewPosition.CreatedAt = DateTime.Now;
                _context.Positions.Add(NewPosition);
                await _context.SaveChangesAsync();
                SuccessMessage = $"Position '{NewPosition.Name}' has been created successfully.";
                return RedirectToPage();
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error creating position: {ex.Message}";
                await OnGetAsync();
                return Page();
            }
        }

        public async Task<IActionResult> OnPostEditAsync(int id, string name, string description, bool isActive)
        {
            // Sanitize inputs
            name = SqlInputSanitizer.SanitizeString(name);
            description = SqlInputSanitizer.SanitizeString(description);
            
            var position = await _context.Positions.FindAsync(id);
            if (position == null)
            {
                ErrorMessage = "Position not found.";
                return RedirectToPage();
            }

            try
            {
                position.Name = name;
                position.Description = description;
                position.IsActive = isActive;

                _context.Update(position);
                await _context.SaveChangesAsync();
                SuccessMessage = $"Position '{position.Name}' has been updated successfully.";
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error updating position: {ex.Message}";
            }

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostToggleStatusAsync(int id)
        {
            var position = await _context.Positions.FindAsync(id);
            if (position == null)
            {
                ErrorMessage = "Position not found.";
                return RedirectToPage();
            }

            try
            {
                position.IsActive = !position.IsActive;
                _context.Update(position);
                await _context.SaveChangesAsync();
                SuccessMessage = $"Position '{position.Name}' has been {(position.IsActive ? "activated" : "deactivated")} successfully.";
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Error toggling position status: {ex.Message}";
            }

            return RedirectToPage();
        }
    }
} 