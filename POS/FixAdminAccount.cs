using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using POS.Data;
using POS.Models;
using POS.Services;

public static class FixAdminAccount
{
    public static async Task FixAdmin(IServiceProvider services)
    {
        try
        {
            // Get required services
            using var scope = services.CreateScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var encryptionService = scope.ServiceProvider.GetRequiredService<IEncryptionService>();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

            logger.LogInformation("Checking admin account status...");
            
            // Skip admin account modification to prevent email changes on startup
            logger.LogInformation("Skipping admin account modification to preserve email values.");
            return;

            /* 
            // The following code is commented out to prevent changing emails on startup
            // Get admin accounts first
            var adminUsers = await userManager.GetUsersInRoleAsync("Admin");
            var adminAccount = adminUsers.FirstOrDefault(u => u.IsAdmin);

            if (adminAccount == null)
            {
                logger.LogError("No admin account found");
                return;
            }

            // Check if fix is needed by trying to decrypt the admin email
            bool needsFix = false;
            try
            {
                string decryptedEmail = encryptionService.Decrypt(adminAccount.Email);
                // If email doesn't match expected format, it needs fixing
                if (decryptedEmail != "admin@example.com")
                {
                    needsFix = true;
                }
            }
            catch
            {
                // If decryption fails, it needs fixing
                needsFix = true;
            }
            
            if (!needsFix)
            {
                logger.LogInformation("Admin account email appears to be correctly encrypted. Skipping fix.");
                return;
            }

            logger.LogInformation($"Found admin account: {adminAccount.UserName}, Email: {adminAccount.Email}");

            // Get current shift value
            int shiftValue = encryptionService.GetShiftValue();
            logger.LogInformation($"Current shift value: {shiftValue}");

            // Correct values
            const string correctEmail = "admin@example.com";
            const string correctUsername = "admin";

            // Encrypt with current shift value
            string encryptedEmail = encryptionService.Encrypt(correctEmail);
            string encryptedUsername = encryptionService.Encrypt(correctUsername);

            logger.LogInformation($"Encrypting '{correctEmail}' with shift {shiftValue} => '{encryptedEmail}'");
            logger.LogInformation($"Encrypting '{correctUsername}' with shift {shiftValue} => '{encryptedUsername}'");

            // Update admin account
            adminAccount.Email = encryptedEmail;
            adminAccount.NormalizedEmail = encryptedEmail.ToUpper();
            adminAccount.UserName = encryptedUsername;
            adminAccount.NormalizedUserName = encryptedUsername.ToUpper();

            // Save changes
            var result = await userManager.UpdateAsync(adminAccount);

            if (result.Succeeded)
            {
                logger.LogInformation("Admin account updated successfully");
                
                // Store the fix date in a preference using admin's ID
                try
                {
                    var adminFixFlag = await context.UserPreferences
                        .FirstOrDefaultAsync(p => p.Key == "AdminAccountFixed" && p.UserId == adminAccount.Id);
                        
                    if (adminFixFlag == null)
                    {
                        context.UserPreferences.Add(new UserPreference
                        {
                            UserId = adminAccount.Id, // Use admin's actual ID
                            Key = "AdminAccountFixed",
                            Value = "true"
                        });
                        await context.SaveChangesAsync();
                        logger.LogInformation("Admin fix flag set to prevent reapplication on restart");
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to set admin fix flag, but fix was completed");
                }
            }
            else
            {
                logger.LogError("Failed to update admin account: " + string.Join(", ", result.Errors.Select(e => e.Description)));
            }
            */
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
} 