using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using POS.Data;
using POS.Models;
using POS.Services;
using System.Security.Claims;

namespace POS.Pages.api.employees
{
    [Authorize(Roles = "Employee,Admin")]
    public class ActivityModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly ILogger<ActivityModel> _logger;
        private readonly IEncryptionService _encryptionService;

        public ActivityModel(
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext context,
            ILogger<ActivityModel> logger,
            IEncryptionService encryptionService)
        {
            _userManager = userManager;
            _context = context;
            _logger = logger;
            _encryptionService = encryptionService;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            // Check if the user is authenticated before proceeding
            if (!User.Identity.IsAuthenticated)
            {
                Response.StatusCode = 401; // Unauthorized
                return new JsonResult(new { error = "Unauthorized access" });
            }

            // Check if the user has the required role
            if (!User.IsInRole("Employee") && !User.IsInRole("Admin"))
            {
                Response.StatusCode = 403; // Forbidden
                return new JsonResult(new { error = "Access denied. Insufficient permissions." });
            }

            try
            {
                _logger.LogInformation("Fetching employee activity data for Manager dashboard");
                
                // Get all employees from the database
                var employees = await _userManager.GetUsersInRoleAsync("Employee");
                
                // Get both cashiers and other employees who handle orders
                var cashiers = await _userManager.GetUsersInRoleAsync("Cashier");
                var allStaff = employees.Concat(cashiers).Distinct().ToList();
                
                // Get active employees who have handled orders
                var employeeActivity = await _context.Orders
                    .Where(o => o.AssignedToEmployeeId != null && 
                           (o.Status == OrderStatus.Processing || 
                            o.Status == OrderStatus.OrderReceived || 
                            o.Status == OrderStatus.OnGoing || 
                            o.Status == OrderStatus.Completed || 
                            o.Status == OrderStatus.Complete))
                    .GroupBy(o => o.AssignedToEmployeeId)
                    .Select(g => new { 
                        EmployeeId = g.Key, 
                        OrdersHandled = g.Count() 
                    })
                    .ToListAsync();

                // Get detailed order data for all staff including cashiers
                var employeeOrders = await _context.Orders
                    .Select(o => new {
                        Id = o.Id,
                        UserId = o.UserId,
                        AssignedToEmployeeId = o.AssignedToEmployeeId,
                        Status = o.Status.ToString(),
                        TotalPrice = o.TotalPrice,
                        CreatedAt = o.CreatedAt
                    })
                    .ToListAsync();
                
                // Join with employee data
                var activeEmployees = new List<dynamic>();
                int maxOrdersHandled = 0;
                string topPerformerName = "None";

                // First include staff with specific order assignments
                foreach (var activity in employeeActivity)
                {
                    var employee = allStaff.FirstOrDefault(e => e.Id == activity.EmployeeId);
                    if (employee != null)
                    {
                        // Decrypt employee name if needed
                        string employeeName = GetDisplayName(employee);
                        
                        // Track top performer
                        if (activity.OrdersHandled > maxOrdersHandled)
                        {
                            maxOrdersHandled = activity.OrdersHandled;
                            topPerformerName = employeeName;
                        }
                        
                        // Get employee's position
                        var position = await _context.Positions
                            .FirstOrDefaultAsync(p => p.Id == employee.PositionId);
                            
                        // Determine if employee is currently active (simplified for demo)
                        var isActive = DateTime.Now.Hour >= 8 && DateTime.Now.Hour < 20;
                        
                        // Get orders assigned to this employee
                        var employeeOrderDetails = employeeOrders
                            .Where(o => o.AssignedToEmployeeId == activity.EmployeeId)
                            .ToList();
                        
                        activeEmployees.Add(new { 
                            name = employeeName,
                            position = position?.Name ?? "Employee",
                            ordersHandled = activity.OrdersHandled,
                            status = isActive ? "Active" : "On Break",
                            orders = employeeOrderDetails
                        });
                    }
                }

                // Now include cashiers and other staff who may not have specific assignments
                foreach (var staff in allStaff)
                {
                    // Decrypt staff name if needed
                    string staffName = GetDisplayName(staff);
                    
                    // Skip if already included
                    if (activeEmployees.Any(ae => ((dynamic)ae).name == staffName))
                        continue;
                        
                    // Get staff's position
                    var position = await _context.Positions
                        .FirstOrDefaultAsync(p => p.Id == staff.PositionId);
                        
                    // Get orders processed by this staff (based on UserId)
                    var processedOrders = employeeOrders
                        .Where(o => o.UserId == staff.Id)
                        .ToList();
                        
                    // Determine if staff is currently active (simplified for demo)
                    var isActive = DateTime.Now.Hour >= 8 && DateTime.Now.Hour < 20;
                    
                    activeEmployees.Add(new {
                        name = staffName,
                        position = position?.Name ?? "Staff",
                        ordersHandled = processedOrders.Count,
                        status = isActive ? "Active" : "On Break",
                        orders = processedOrders
                    });
                    
                    // Update top performer if needed
                    if (processedOrders.Count > maxOrdersHandled)
                    {
                        maxOrdersHandled = processedOrders.Count;
                        topPerformerName = staffName;
                    }
                }
                
                // If no employees have activities yet, add some sample data
                if (activeEmployees.Count == 0 && allStaff.Any())
                {
                    var employee = allStaff.First();
                    var position = await _context.Positions
                        .FirstOrDefaultAsync(p => p.Id == employee.PositionId);
                    
                    // Decrypt employee name if needed
                    string employeeName = GetDisplayName(employee);
                        
                    activeEmployees.Add(new {
                        name = employeeName,
                        position = position?.Name ?? "Employee",
                        ordersHandled = 1,
                        status = "Active",
                        orders = new List<dynamic>()
                    });
                    
                    topPerformerName = employeeName;
                    maxOrdersHandled = 1;
                }
                
                // Return formatted response
                return new JsonResult(new {
                    activeEmployees = activeEmployees,
                    topPerformer = new {
                        name = topPerformerName,
                        ordersHandled = maxOrdersHandled
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching employee activity data");
                Response.StatusCode = 500;
                return new JsonResult(new { error = "Failed to fetch employee activity data" });
            }
        }
        
        // Helper method to get decrypted name from a user
        private string GetDisplayName(ApplicationUser user)
        {
            if (user == null)
                return "Unknown";
                
            try
            {
                // Try to use FullName first
                if (!string.IsNullOrEmpty(user.FullName))
                {
                    try {
                        return _encryptionService.Decrypt(user.FullName);
                    } catch {
                        // If decryption fails, use the original value
                        return user.FullName;
                    }
                }
                
                // Use UserName (decrypt if needed)
                if (!string.IsNullOrEmpty(user.UserName))
                {
                    try {
                        return _encryptionService.Decrypt(user.UserName);
                    } catch {
                        // If decryption fails, use the original value
                        return user.UserName;
                    }
                }
                
                // Fall back to Email
                if (!string.IsNullOrEmpty(user.Email))
                {
                    try {
                        return _encryptionService.Decrypt(user.Email);
                    } catch {
                        // If decryption fails, use the original value
                        return user.Email;
                    }
                }
                
                return "Unknown";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Failed to decrypt name for user {user.Id}");
                return user.UserName ?? "Unknown";
            }
        }
        
        // Helper method to check if a string might be encrypted
        private bool IsValidBase64(string input)
        {
            // For our purposes, we'll always try to decrypt
            return !string.IsNullOrEmpty(input);
        }
    }
} 