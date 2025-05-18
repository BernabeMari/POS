using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using POS.Services;
using System.Data.SqlClient;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);

// Configure connection string more securely
var connectionStringBuilder = new SqlConnectionStringBuilder
{
    DataSource = "zybpos20.mssql.somee.com",
    InitialCatalog = "zybpos20",
    UserID = "zybpos_SQLLogin_1",
    Password = "uc941sbrza",
    WorkstationID = "zybpos20.mssql.somee.com",
    PersistSecurityInfo = false,
    TrustServerCertificate = true,
    PacketSize = 4096,
    ConnectTimeout = 30
};

var connectionString = connectionStringBuilder.ConnectionString;

// Add Kestrel server options to increase limits for image uploads
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.Limits.MaxRequestBodySize = 50 * 1024 * 1024; // 50 MB
});

// Configure JSON options to handle larger payloads
builder.Services.Configure<JsonOptions>(options =>
{
    options.JsonSerializerOptions.DefaultBufferSize = 40 * 1024 * 1024; // 40 MB
});

// Register connection string with the name "DefaultConnection"
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Configuration["ConnectionStrings:DefaultConnection"] = connectionString;

// Add Identity services
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    
    // Configure username validator to accept Base64 characters (for encrypted usernames)
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._+/=";
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Add custom services
builder.Services.AddScoped<IPageTemplateService, PageTemplateService>();
builder.Services.AddScoped<IPageElementService, PageElementService>();
builder.Services.AddScoped<ILoginAttemptService, LoginAttemptService>();
builder.Services.AddScoped<IEncryptionService, EncryptionService>();
builder.Services.AddScoped<IStockService, StockService>();
builder.Services.AddScoped<IOrderService, OrderService>();
builder.Services.AddScoped<IProductService, ProductService>();
builder.Services.AddScoped<IPayPalService, PayPalService>();
builder.Services.AddScoped<ICartService, CartService>();

// Add our custom claims transformation
builder.Services.AddScoped<IClaimsTransformation, DecryptedUserNameClaimsTransformation>();

// Add global page filters for security
builder.Services.AddRazorPages()
    .AddMvcOptions(options => 
    {
        // Add sanitization filter for all pages, especially admin area
        options.Filters.Add<AdminSanitizationPageFilter>();
    })
    .AddNewtonsoftJson();

// Add controller configuration with filters
builder.Services.AddControllersWithViews(options =>
{
    // Add sanitization filter for all controllers
    options.Filters.Add<AdminSanitizationPageFilter>();
});

// Add PayPal configuration
builder.Configuration["PayPal:ClientId"] = "AXX4_-PsWrRCWUkF0PF6tPa12WyNGL3-MtOZlYC6DxFJjwoxUUssSdRfjNd7wFNkGKUdB9oXSq8I6ePr";
builder.Configuration["PayPal:ClientSecret"] = "EHnlE2LugBOJ3KrsqyMz7WPxQdVZenC9_d9QB5Ri62DH2AU3OlKUeZd4gqONSma9xf-EjxnX13Rk-cwi";
   builder.Configuration["PayPal:ReturnUrl"] = "http://localhost:5050/Test/Success";
   builder.Configuration["PayPal:CancelUrl"] = "http://localhost:5050/Test/Cancel";

// Add session support
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Add Razor pages with areas support
builder.Services.AddRazorPages(options =>
{
    // Authorize the Admin area
    options.Conventions.AuthorizeAreaFolder("Admin", "/", "RequireAdministratorRole");
    
    // Authorize the Employee area
    options.Conventions.AuthorizeAreaFolder("Employee", "/", "RequireEmployeeRole");
});

// Add Authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdministratorRole", policy => policy.RequireRole("Admin"));
    options.AddPolicy("RequireEmployeeRole", policy => policy.RequireRole("Employee"));
});

// Configure cookie policy
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/AccessDenied";
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromDays(7);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    // Add development-specific middleware
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// Use session middleware
app.UseSession();

// Map area routes with explicit mappings
app.MapAreaControllerRoute(
    name: "admin_area",
    areaName: "Admin",
    pattern: "Admin/{controller=Home}/{action=Index}/{id?}");

app.MapAreaControllerRoute(
    name: "user_area",
    areaName: "User",
    pattern: "User/{controller=Home}/{action=Index}/{id?}");

app.MapAreaControllerRoute(
    name: "employee_area",
    areaName: "Employee",
    pattern: "Employee/{controller=Home}/{action=Index}/{id?}");

// Map default controller route
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Map Razor Pages
app.MapRazorPages();

// Seed the database
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        await SeedData.Initialize(services);
        
        // Skip the encryption of existing usernames since it causes emails to change on restart
        // await EncryptExistingUserNames(services);
        
        // Fix admin account encryption if needed
        await FixAdminAccount.FixAdmin(services);
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding the database.");
    }
}

app.Run();

// Method to encrypt existing usernames
async Task EncryptExistingUserNames(IServiceProvider serviceProvider)
{
    var context = serviceProvider.GetRequiredService<ApplicationDbContext>();
    var encryptionService = serviceProvider.GetRequiredService<IEncryptionService>();
    var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
    var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();

    // Check if encryption has already been applied by examining user data patterns
    // If at least one user has Base64 formatted email, assume encryption was applied
    var users = await context.Users.ToListAsync();
    if (users.Count > 0 && users.Any(u => IsValidBase64(u.Email)))
    {
        logger.LogInformation("Detected previously encrypted data. Skipping re-encryption.");
        return;
    }

    logger.LogInformation($"Starting encryption of user data for {users.Count} users");

    int encryptedCount = 0;
    string adminUserId = null;

    foreach (var user in users)
    {
        try
        {
            // Store admin user ID for later flag setting
            if (user.IsAdmin)
            {
                adminUserId = user.Id;
            }

            bool isChanged = false;
            logger.LogInformation($"Processing user: {user.Id}, Email: {user.Email}, UserName: {user.UserName}");
            
            // Check if username is already encrypted
            if (!IsValidBase64(user.UserName) || !TryDecrypt(encryptionService, user.UserName, out _))
            {
                // Username is not encrypted, encrypt it
                string originalUserName = user.UserName;
                user.UserName = encryptionService.Encrypt(originalUserName);
                user.NormalizedUserName = user.UserName.ToUpper();
                isChanged = true;
                logger.LogInformation($"Encrypted username for user {user.Id}: {originalUserName} -> {user.UserName}");
            }
            
            // Check if email is already encrypted
            if (!IsValidBase64(user.Email) || !TryDecrypt(encryptionService, user.Email, out _))
            {
                // Email is not encrypted, encrypt it
                string originalEmail = user.Email;
                user.Email = encryptionService.Encrypt(originalEmail);
                user.NormalizedEmail = user.Email.ToUpper();
                isChanged = true;
                logger.LogInformation($"Encrypted email for user {user.Id}: {originalEmail} -> {user.Email}");
            }

            if (isChanged)
            {
                encryptedCount++;
                await context.SaveChangesAsync();
                logger.LogInformation($"Saved changes for user {user.Id}");
            }
            else
            {
                logger.LogInformation($"No changes needed for user {user.Id}");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, $"Error encrypting data for user {user.Id}");
        }
    }

    logger.LogInformation($"Encrypted data for {encryptedCount} users");
    
    // Only try to set the flag if we have a valid admin user ID and made changes
    if (adminUserId != null && encryptedCount > 0)
    {
        try
        {
            // Check if the flag already exists
            var encryptionFlag = await context.UserPreferences
                .FirstOrDefaultAsync(p => p.Key == "EncryptionApplied" && p.UserId == adminUserId);
                
            if (encryptionFlag == null)
            {
                context.UserPreferences.Add(new UserPreference
                {
                    UserId = adminUserId, // Use admin's ID instead of "system"
                    Key = "EncryptionApplied",
                    Value = "true"
                });
                await context.SaveChangesAsync();
                logger.LogInformation("Encryption flag set to prevent re-encryption on restart");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to set encryption flag, but encryption was completed");
        }
    }
    
    // Check for admin user that needs special handling
    var adminEmail = "admin@example.com";
    var encryptedAdminEmail = encryptionService.Encrypt(adminEmail);

    // Try to find the admin user by both original and encrypted email
    var adminUser = await context.Users.FirstOrDefaultAsync(u => 
        u.Email == adminEmail || 
        u.Email == encryptedAdminEmail || 
        u.NormalizedEmail == adminEmail.ToUpper() || 
        u.NormalizedEmail == encryptedAdminEmail.ToUpper() ||
        u.UserName == "admin");
    
    if (adminUser != null)
    {
        logger.LogInformation($"Found admin user: {adminUser.Id}");
        // Make sure admin user has its properties properly set
        adminUser.IsAdmin = true;
        
        // Check if admin is in Admin role
        var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        if (!await roleManager.RoleExistsAsync("Admin"))
        {
            await roleManager.CreateAsync(new IdentityRole("Admin"));
            logger.LogInformation("Created Admin role");
        }
        
        if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
        {
            await userManager.AddToRoleAsync(adminUser, "Admin");
            logger.LogInformation("Added admin user to Admin role");
        }
        
        await context.SaveChangesAsync();
        logger.LogInformation("Admin user updated");
    }
    else
    {
        logger.LogWarning("Admin user not found");
    }
}

// Helper method to check if a string is valid Base64
bool IsValidBase64(string input)
{
    if (string.IsNullOrEmpty(input))
        return false;
        
    try
    {
        Convert.FromBase64String(input);
        return (input.Length % 4 == 0) && Regex.IsMatch(input, @"^[a-zA-Z0-9\+/]*={0,3}$");
    }
    catch
    {
        return false;
    }
}

// Helper method to try decrypting a value
bool TryDecrypt(IEncryptionService encryptionService, string input, out string decrypted)
{
    decrypted = null;
    try
    {
        decrypted = encryptionService.Decrypt(input);
        return true;
    }
    catch
    {
        return false;
    }
}
