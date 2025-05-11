using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using POS.Models;
using POS.Services;
using Microsoft.Extensions.Logging;

namespace POS.Data
{
    public static class SeedData
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using var context = new ApplicationDbContext(
                serviceProvider.GetRequiredService<DbContextOptions<ApplicationDbContext>>());

            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var encryptionService = serviceProvider.GetRequiredService<IEncryptionService>();
            var logger = serviceProvider.GetRequiredService<ILogger<ApplicationDbContext>>();

            // Ensure database is created
            context.Database.EnsureCreated();

            // Create roles if they don't exist
            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                await roleManager.CreateAsync(new IdentityRole("Admin"));
            }

            if (!await roleManager.RoleExistsAsync("User"))
            {
                await roleManager.CreateAsync(new IdentityRole("User"));
            }
            
            if (!await roleManager.RoleExistsAsync("Employee"))
            {
                await roleManager.CreateAsync(new IdentityRole("Employee"));
            }

            // Create admin user if it doesn't exist
            var adminEmail = "admin@example.com";
            var encryptedAdminEmail = encryptionService.Encrypt(adminEmail);
            
            // Try to find by either encrypted or unencrypted email
            var adminUser = await context.Users.FirstOrDefaultAsync(u => 
                u.Email == adminEmail ||
                u.Email == encryptedAdminEmail ||
                u.NormalizedEmail == adminEmail.ToUpper() ||
                u.NormalizedEmail == encryptedAdminEmail.ToUpper());

            if (adminUser == null)
            {
                logger.LogInformation("Admin user not found, creating new admin user with encrypted credentials");
                
                // Encrypt admin credentials
                string encryptedUserName = encryptionService.Encrypt("admin");
                string encryptedFullName = encryptionService.Encrypt("System Administrator");
                
                adminUser = new ApplicationUser
                {
                    UserName = encryptedUserName,
                    NormalizedUserName = encryptedUserName.ToUpper(),
                    Email = encryptedAdminEmail,
                    NormalizedEmail = encryptedAdminEmail.ToUpper(),
                    FullName = encryptedFullName,
                    IsAdmin = true,
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(adminUser, "Admin123!");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                    logger.LogInformation("Admin user created successfully with encrypted credentials");
                }
                else
                {
                    logger.LogError("Failed to create admin user: {Errors}", 
                        string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
            else
            {
                logger.LogInformation("Admin user already exists, skipping creation");
            }
            
            // Seed default positions if they don't exist
            if (!context.Positions.Any())
            {
                var positions = new List<Position>
                {
                    new Position { Name = "Manager", Description = "Store manager with full access to management features", IsActive = true },
                    new Position { Name = "Assistant Manager", Description = "Reports to the manager and handles day-to-day operations", IsActive = true },
                    new Position { Name = "Cashier", Description = "Processes customer transactions", IsActive = true },
                    new Position { Name = "Inventory Clerk", Description = "Manages stock and inventory", IsActive = true }
                };
                
                try
                {
                    context.Positions.AddRange(positions);
                    await context.SaveChangesAsync();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error seeding positions: {ex.Message}");
                    // Continue with other seeding even if positions fail
                }
            }

            // Create default templates if none exist
            if (!context.PageTemplates.Any())
            {
                CreateDefaultTemplates(context);
            }

            await context.SaveChangesAsync();
        }

        private static void CreateDefaultTemplates(ApplicationDbContext context)
        {
            // Login Template
            var loginTemplate = new PageTemplate
            {
                Name = "Login",
                Description = "Default login page template",
                BackgroundColor = "#FFFFFF",
                IsActive = true,
                CreatedAt = DateTime.Now
            };

            loginTemplate.Elements.Add(new PageElement
            {
                PageName = "Login",
                ElementType = "InputField",
                ElementId = "email-input",
                Text = "Email",
                PositionX = 100,
                PositionY = 100,
                Width = 300,
                Height = 40
            });

            loginTemplate.Elements.Add(new PageElement
            {
                PageName = "Login",
                ElementType = "InputField",
                ElementId = "password-input",
                Text = "Password",
                PositionX = 100,
                PositionY = 160,
                Width = 300,
                Height = 40
            });

            loginTemplate.Elements.Add(new PageElement
            {
                PageName = "Login",
                ElementType = "Button",
                ElementId = "login-button",
                Text = "Login",
                Color = "#007bff",
                PositionX = 100,
                PositionY = 220,
                Width = 300,
                Height = 40
            });

            loginTemplate.Elements.Add(new PageElement
            {
                PageName = "Login",
                ElementType = "Label",
                ElementId = "signup-link",
                Text = "Don't have an account? Register here",
                Color = "#007bff",
                PositionX = 100,
                PositionY = 280,
                Width = 300,
                Height = 20
            });

            context.PageTemplates.Add(loginTemplate);

            // Register Template
            var registerTemplate = new PageTemplate
            {
                Name = "Register",
                Description = "Default register page template",
                BackgroundColor = "#FFFFFF",
                IsActive = true,
                CreatedAt = DateTime.Now
            };

            // Add register elements (similar to login elements)
            registerTemplate.Elements.Add(new PageElement
            {
                PageName = "Register",
                ElementType = "InputField",
                ElementId = "username-input",
                Text = "Username",
                PositionX = 100,
                PositionY = 100,
                Width = 300,
                Height = 40
            });

            registerTemplate.Elements.Add(new PageElement
            {
                PageName = "Register",
                ElementType = "InputField",
                ElementId = "email-input",
                Text = "Email",
                PositionX = 100,
                PositionY = 160,
                Width = 300,
                Height = 40
            });

            // Add more elements as needed

            context.PageTemplates.Add(registerTemplate);
        }
    }
}