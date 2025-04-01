using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using POS.Services;

var builder = WebApplication.CreateBuilder(args);

// Add database connection
var connectionString = "workstation id=cybersec-pos.mssql.somee.com;packet size=4096;user id=zyber202003_SQLLogin_1;pwd=3rm4crqfsd;data source=cybersec-pos.mssql.somee.com;persist security info=False;initial catalog=cybersec-pos;TrustServerCertificate=True";

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Add Identity services
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Add custom services
builder.Services.AddScoped<IPageTemplateService, PageTemplateService>();
builder.Services.AddScoped<IPageElementService, PageElementService>();
builder.Services.AddScoped<ILoginAttemptService, LoginAttemptService>();
builder.Services.AddScoped<IOrderService, OrderService>();
builder.Services.AddScoped<IProductService, ProductService>();

// Add Razor pages with areas support
builder.Services.AddRazorPages(options =>
{
    // Authorize the Admin area
    options.Conventions.AuthorizeAreaFolder("Admin", "/", "RequireAdministratorRole");
    
    // Authorize the Employee area
    options.Conventions.AuthorizeAreaFolder("Employee", "/", "RequireEmployeeRole");
})
.AddNewtonsoftJson();

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
if (!app.Environment.IsDevelopment())
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

// Map Razor Pages
app.MapRazorPages();

// Seed the database
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        await SeedData.Initialize(services);
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding the database.");
    }
}

app.Run();
