using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Text.Json;

namespace POS.Areas.Admin.Pages
{
    public class PageEditorModel : PageModel
    {
        private readonly IPageTemplateService _templateService;
        private readonly IPageElementService _elementService;

        public PageEditorModel(IPageTemplateService templateService, IPageElementService elementService)
        {
            _templateService = templateService;
            _elementService = elementService;
        }

        [BindProperty(SupportsGet = true)]
        public string CurrentPage { get; set; } = "Login";

        public PageTemplate CurrentTemplate { get; set; }
        
        public string TemplateElementsJson { get; set; }
        
        public string BackgroundColor { get; set; } = "#ffffff";
        
        // Default elements for the Register page template
        private readonly List<ElementModel> DefaultRegisterElements = new List<ElementModel> 
        {
            new ElementModel { Id = "fullname-input", Type = "InputField", Text = "Full Name", X = 100, Y = 100, Width = 300, Height = 40, Color = "#000000" },
            new ElementModel { Id = "username-input", Type = "InputField", Text = "Username", X = 100, Y = 160, Width = 300, Height = 40, Color = "#000000" },
            new ElementModel { Id = "email-input", Type = "InputField", Text = "Email Address", X = 100, Y = 220, Width = 300, Height = 40, Color = "#000000" },
            new ElementModel { Id = "password-input", Type = "InputField", Text = "Password", X = 100, Y = 280, Width = 300, Height = 40, Color = "#000000" },
            new ElementModel { Id = "confirm-password", Type = "InputField", Text = "Confirm Password", X = 100, Y = 340, Width = 300, Height = 40, Color = "#000000" },
            new ElementModel { Id = "senior-pwd-label", Type = "Label", Text = "Are you a Senior Citizen or PWD? (Optional)", X = 100, Y = 400, Width = 300, Height = 30, Color = "#000000" },
            new ElementModel { Id = "senior-pwd-select", Type = "Checkbox", Text = "Yes", X = 100, Y = 430, Width = 50, Height = 30, Color = "#000000" },
            new ElementModel { Id = "qr-scanner-container", Type = "ContentPanel", Text = "QR Scanner", X = 100, Y = 470, Width = 300, Height = 200, Color = "#f8f9fa", AdditionalStyles = "display: none; border: 1px solid #ddd; border-radius: 4px;" },
            new ElementModel { Id = "scan-qr-button", Type = "Button", Text = "Scan QR Code", X = 160, Y = 430, Width = 150, Height = 30, Color = "#28a745", AdditionalStyles = "display: none;" },
            new ElementModel { Id = "qr-result-label", Type = "Label", Text = "", X = 100, Y = 680, Width = 300, Height = 30, Color = "#000000", AdditionalStyles = "display: none;" },
            new ElementModel { Id = "terms-checkbox", Type = "Checkbox", Text = "I agree to the Terms and Conditions", X = 100, Y = 730, Width = 300, Height = 30, Color = "#000000" },
            new ElementModel { Id = "register-button", Type = "Button", Text = "Create Account", X = 100, Y = 780, Width = 300, Height = 40, Color = "#28a745" },
            new ElementModel { Id = "login-link", Type = "Label", Text = "Already have an account? Login here", X = 100, Y = 840, Width = 300, Height = 20, Color = "#007bff" }
        };
        
        // Default elements for the Cashier Dashboard template
        private readonly List<ElementModel> DefaultEmployeeDashboardElements = new List<ElementModel> 
        {
            // Header section
            new ElementModel { Id = "welcome-label", Type = "Label", Text = "Cashier Dashboard", X = 20, Y = 20, Width = 400, Height = 40, Color = "#343a40" },
            new ElementModel { Id = "employee-status", Type = "Label", Text = "Logged in as Cashier", X = 620, Y = 20, Width = 300, Height = 30, Color = "#6c757d" },
            new ElementModel { Id = "logout-button", Type = "Button", Text = "Logout", X = 830, Y = 20, Width = 100, Height = 40, Color = "#dc3545" },
            
            // New Orders Panel
            new ElementModel { Id = "orders-panel", Type = "ContentPanel", Text = "New Orders", X = 20, Y = 80, Width = 600, Height = 300, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" },
            
            // My Tasks Panel (Assigned Orders)
            new ElementModel { Id = "my-tasks", Type = "ContentPanel", Text = "My Assigned Orders", X = 640, Y = 80, Width = 320, Height = 300, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" },
            
            // Order History Panel
            new ElementModel { Id = "orders-history", Type = "ContentPanel", Text = "Order History", X = 20, Y = 400, Width = 940, Height = 250, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" },
            
            // Quick Status Update Section
            new ElementModel { Id = "status-update-label", Type = "Label", Text = "Quick Status Update", X = 640, Y = 390, Width = 320, Height = 30, Color = "#343a40" },
            new ElementModel { Id = "order-id-input", Type = "InputField", Text = "Order ID", X = 640, Y = 430, Width = 150, Height = 40, Color = "#000000" },
            new ElementModel { Id = "status-dropdown", Type = "InputField", Text = "Status", X = 800, Y = 430, Width = 160, Height = 40, Color = "#000000" },
            new ElementModel { Id = "update-status-button", Type = "Button", Text = "Update Status", X = 640, Y = 480, Width = 320, Height = 40, Color = "#007bff" },
            
            // Notifications Toggle
            new ElementModel { Id = "notifications-toggle", Type = "Button", Text = "Toggle Notifications", X = 640, Y = 530, Width = 320, Height = 40, Color = "#17a2b8" }
        };
        
        // Default elements for the Manager Dashboard template
        private readonly List<ElementModel> DefaultManagerDashboardElements = new List<ElementModel> 
        {
            // Header section
            new ElementModel { Id = "welcome-label", Type = "Label", Text = "Manager Dashboard", X = 20, Y = 20, Width = 400, Height = 40, Color = "#343a40" },
            new ElementModel { Id = "manager-status", Type = "Label", Text = "Logged in as Manager", X = 620, Y = 20, Width = 300, Height = 30, Color = "#6c757d" },
            new ElementModel { Id = "logout-button", Type = "Button", Text = "Logout", X = 830, Y = 20, Width = 100, Height = 40, Color = "#dc3545" },
            
            // Store Performance Panel
            new ElementModel { Id = "store-performance", Type = "ContentPanel", Text = "Store Performance", X = 20, Y = 80, Width = 600, Height = 300, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" },
            
            // Staff Activity Panel
            new ElementModel { Id = "staff-activity", Type = "ContentPanel", Text = "Staff Activity", X = 640, Y = 80, Width = 320, Height = 300, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" },
            
            // Recent Orders Panel
            new ElementModel { Id = "recent-orders", Type = "ContentPanel", Text = "Recent Orders", X = 20, Y = 400, Width = 600, Height = 250, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" },
            
            // Inventory Alerts Panel
            new ElementModel { Id = "inventory-alerts", Type = "ContentPanel", Text = "Inventory Alerts", X = 640, Y = 400, Width = 320, Height = 250, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" }
        };
        
        // Default elements for the Assistant Manager Dashboard template
        private readonly List<ElementModel> DefaultAssistantManagerDashboardElements = new List<ElementModel> 
        {
            // Header section
            new ElementModel { Id = "welcome-label", Type = "Label", Text = "Assistant Manager Dashboard", X = 20, Y = 20, Width = 400, Height = 40, Color = "#343a40" },
            new ElementModel { Id = "assistant-manager-status", Type = "Label", Text = "Logged in as Assistant Manager", X = 620, Y = 20, Width = 300, Height = 30, Color = "#6c757d" },
            new ElementModel { Id = "logout-button", Type = "Button", Text = "Logout", X = 830, Y = 20, Width = 100, Height = 40, Color = "#dc3545" },
            
            // Staff Activity Panel - Moved to the left side where Store Performance was
            new ElementModel { Id = "staff-activity", Type = "ContentPanel", Text = "Staff Activity", X = 20, Y = 80, Width = 450, Height = 300, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); overflow-y: auto; overflow-x: hidden; max-height: 300px; display: block;" },
            
            // Inventory Alerts Panel - Moved to the right side
            new ElementModel { Id = "inventory-alerts", Type = "ContentPanel", Text = "Inventory Alerts", X = 490, Y = 80, Width = 450, Height = 300, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); overflow-y: auto; overflow-x: hidden; max-height: 300px; display: block;" },
            
            // Recent Orders Panel - Moved down and widened
            new ElementModel { Id = "recent-orders", Type = "ContentPanel", Text = "Recent Orders", X = 20, Y = 400, Width = 920, Height = 250, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); overflow-y: auto; overflow-x: hidden; max-height: 250px; display: block;" }
        };
        
        // Default elements for the Inventory Clerk Dashboard template
        private readonly List<ElementModel> DefaultInventoryClerkDashboardElements = new List<ElementModel> 
        {
            // Header section
            new ElementModel { Id = "welcome-label", Type = "Label", Text = "Inventory Clerk Dashboard", X = 20, Y = 20, Width = 400, Height = 40, Color = "#343a40" },
            new ElementModel { Id = "inventory-clerk-status", Type = "Label", Text = "Logged in as Inventory Clerk", X = 580, Y = 20, Width = 340, Height = 30, Color = "#6c757d" },
            new ElementModel { Id = "logout-button", Type = "Button", Text = "Logout", X = 830, Y = 20, Width = 100, Height = 40, Color = "#dc3545" },
            
            // Product Inventory Panel
            new ElementModel { Id = "product-inventory", Type = "ContentPanel", Text = "Product Inventory", X = 20, Y = 80, Width = 700, Height = 400, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" },
            
            // Inventory Summary Panel
            new ElementModel { Id = "inventory-summary", Type = "ContentPanel", Text = "Inventory Summary", X = 740, Y = 80, Width = 220, Height = 150, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" },
            
            // Pending Orders Panel
            new ElementModel { Id = "pending-orders", Type = "ContentPanel", Text = "Pending Orders", X = 740, Y = 250, Width = 220, Height = 200, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" },
            
            // Quick Actions Panel
            new ElementModel { Id = "quick-actions", Type = "ContentPanel", Text = "Quick Actions", X = 740, Y = 470, Width = 220, Height = 180, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" }
        };
        
        // Default elements for the User Dashboard template
        private readonly List<ElementModel> DefaultDashboardElements = new List<ElementModel>();  // Empty list, no default content panel
        
        // Default elements for the My Orders page template
        private readonly List<ElementModel> DefaultMyOrdersElements = new List<ElementModel> 
        {
            // Header section
            new ElementModel { Id = "welcome-label", Type = "Label", Text = "My Orders", X = 20, Y = 20, Width = 400, Height = 40, Color = "#343a40" },
            
            // Orders table panel
            new ElementModel { Id = "orders-table", Type = "ContentPanel", Text = "Orders", X = 20, Y = 80, Width = 940, Height = 400, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); overflow-y: auto; overflow-x: hidden; max-height: 400px; display: block;" },
            
            // Back to Dashboard button
            new ElementModel { Id = "back-button", Type = "Button", Text = "Back to Dashboard", X = 20, Y = 500, Width = 200, Height = 40, Color = "#007bff" }
        };

        public async Task<IActionResult> OnGetAsync()
        {
            // Check if there's a template for the current page
            CurrentTemplate = await _templateService.GetTemplateByNameAsync(CurrentPage);
            
            if (CurrentTemplate != null)
            {
                BackgroundColor = CurrentTemplate.BackgroundColor;
                
                // For Register page, ensure all required fields are present
                if (CurrentPage == "Register")
                {
                    EnsureRegisterPageFields();
                }
                // For Cashier Dashboard, ensure all required components are present
                else if (CurrentPage == "EmployeeDashboard")
                {
                    EnsureEmployeeDashboardComponents();
                }
                // For Manager Dashboard, ensure all required components are present
                else if (CurrentPage == "ManagerDashboard")
                {
                    EnsureManagerDashboardComponents();
                }
                // For Assistant Manager Dashboard, ensure all required components are present
                else if (CurrentPage == "AssistantManagerDashboard")
                {
                    EnsureAssistantManagerDashboardComponents();
                }
                // For Inventory Clerk Dashboard, ensure all required components are present
                else if (CurrentPage == "InventoryClerkDashboard")
                {
                    EnsureInventoryClerkDashboardComponents();
                }
                // For User Dashboard, ensure all required components are present
                else if (CurrentPage == "Dashboard")
                {
                    EnsureDashboardComponents();
                }
                // For My Orders page, ensure all required components are present
                else if (CurrentPage == "MyOrders")
                {
                    EnsureMyOrdersComponents();
                }
                
                // Serialize elements for JavaScript use
                var elements = CurrentTemplate.Elements.Select(e => new
                {
                    id = e.ElementId,
                    type = e.ElementType,
                    text = e.Text,
                    x = e.PositionX,
                    y = e.PositionY,
                    width = e.Width,
                    height = e.Height,
                    color = e.Color,
                    additionalStyles = e.AdditionalStyles,
                    imageUrl = e.ImageUrl,
                    imageDescription = e.ImageDescription,
                    required = (CurrentPage == "Register" && DefaultRegisterElements.Any(d => d.Id == e.ElementId)) ||
                               (CurrentPage == "EmployeeDashboard" && DefaultEmployeeDashboardElements.Any(d => d.Id == e.ElementId)) ||
                               (CurrentPage == "ManagerDashboard" && DefaultManagerDashboardElements.Any(d => d.Id == e.ElementId)) ||
                               (CurrentPage == "AssistantManagerDashboard" && DefaultAssistantManagerDashboardElements.Any(d => d.Id == e.ElementId)) ||
                               (CurrentPage == "InventoryClerkDashboard" && DefaultInventoryClerkDashboardElements.Any(d => d.Id == e.ElementId)) ||
                               (CurrentPage == "MyOrders" && DefaultMyOrdersElements.Any(d => d.Id == e.ElementId)),
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
                    }).ToList(),
                    // Add product-related properties
                    isProduct = e.IsProduct,
                    productName = e.ProductName,
                    productDescription = e.ProductDescription,
                    productPrice = e.ProductPrice,
                    productStockQuantity = e.ProductStockQuantity,
                    isAvailable = e.IsAvailable,
                    // Add the database ID
                    dbId = e.Id,
                    ingredients = e.Ingredients.Select(ing => new {
                        ingredientName = ing.IngredientName,
                        quantity = ing.Quantity,
                        unit = ing.Unit,
                        notes = ing.Notes
                    }).ToList()
                }).ToList();
                
                TemplateElementsJson = JsonSerializer.Serialize(elements);
            }
            else if (CurrentPage == "Register")
            {
                // For Register page, create a new template with required fields
                CurrentTemplate = new PageTemplate
                {
                    Name = CurrentPage,
                    Description = $"Template for {CurrentPage} page",
                    BackgroundColor = "#ffffff",
                    CreatedAt = DateTime.Now
                };
                
                foreach (var element in DefaultRegisterElements)
                {
                    CurrentTemplate.Elements.Add(new PageElement
                    {
                        PageName = CurrentPage,
                        ElementType = element.Type,
                        ElementId = element.Id,
                        Text = element.Text,
                        Color = element.Color,
                        PositionX = element.X,
                        PositionY = element.Y,
                        Width = element.Width,
                        Height = element.Height
                    });
                }
                
                await _templateService.CreateTemplateAsync(CurrentTemplate);
                
                // Serialize the elements
                var elements = CurrentTemplate.Elements.Select(e => new
                {
                    id = e.ElementId,
                    type = e.ElementType,
                    text = e.Text,
                    x = e.PositionX,
                    y = e.PositionY,
                    width = e.Width,
                    height = e.Height,
                    color = e.Color,
                    additionalStyles = e.AdditionalStyles,
                    imageUrl = e.ImageUrl,
                    imageDescription = e.ImageDescription,
                    required = true,
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
                    }).ToList(),
                    // Add product-related properties
                    isProduct = e.IsProduct,
                    productName = e.ProductName,
                    productDescription = e.ProductDescription,
                    productPrice = e.ProductPrice,
                    productStockQuantity = e.ProductStockQuantity,
                    isAvailable = e.IsAvailable,
                    // Add the database ID
                    dbId = e.Id,
                    ingredients = e.Ingredients.Select(ing => new {
                        ingredientName = ing.IngredientName,
                        quantity = ing.Quantity,
                        unit = ing.Unit,
                        notes = ing.Notes
                    }).ToList()
                }).ToList();
                
                TemplateElementsJson = JsonSerializer.Serialize(elements);
            }
            else if (CurrentPage == "EmployeeDashboard")
            {
                // For Cashier Dashboard, create a new template with required components
                CurrentTemplate = new PageTemplate
                {
                    Name = CurrentPage,
                    Description = $"Template for {CurrentPage}",
                    BackgroundColor = "#f5f5f5",
                    CreatedAt = DateTime.Now
                };
                
                foreach (var element in DefaultEmployeeDashboardElements)
                {
                    CurrentTemplate.Elements.Add(new PageElement
                    {
                        PageName = CurrentPage,
                        ElementType = element.Type,
                        ElementId = element.Id,
                        Text = element.Text,
                        Color = element.Color,
                        PositionX = element.X,
                        PositionY = element.Y,
                        Width = element.Width,
                        Height = element.Height,
                        AdditionalStyles = element.AdditionalStyles
                    });
                }
                
                await _templateService.CreateTemplateAsync(CurrentTemplate);
                
                // Serialize the elements
                var elements = CurrentTemplate.Elements.Select(e => new
                {
                    id = e.ElementId,
                    type = e.ElementType,
                    text = e.Text,
                    x = e.PositionX,
                    y = e.PositionY,
                    width = e.Width,
                    height = e.Height,
                    color = e.Color,
                    additionalStyles = e.AdditionalStyles,
                    imageUrl = e.ImageUrl,
                    imageDescription = e.ImageDescription,
                    required = true,
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
                    }).ToList(),
                    // Add product-related properties
                    isProduct = e.IsProduct,
                    productName = e.ProductName,
                    productDescription = e.ProductDescription,
                    productPrice = e.ProductPrice,
                    productStockQuantity = e.ProductStockQuantity,
                    isAvailable = e.IsAvailable,
                    // Add the database ID
                    dbId = e.Id,
                    ingredients = e.Ingredients.Select(ing => new {
                        ingredientName = ing.IngredientName,
                        quantity = ing.Quantity,
                        unit = ing.Unit,
                        notes = ing.Notes
                    }).ToList()
                }).ToList();
                
                TemplateElementsJson = JsonSerializer.Serialize(elements);
            }
            else if (CurrentPage == "ManagerDashboard")
            {
                // For Manager Dashboard, create a new template with required components
                CurrentTemplate = new PageTemplate
                {
                    Name = CurrentPage,
                    Description = $"Template for {CurrentPage}",
                    BackgroundColor = "#f5f5f5",
                    CreatedAt = DateTime.Now
                };
                
                foreach (var element in DefaultManagerDashboardElements)
                {
                    CurrentTemplate.Elements.Add(new PageElement
                    {
                        PageName = CurrentPage,
                        ElementType = element.Type,
                        ElementId = element.Id,
                        Text = element.Text,
                        Color = element.Color,
                        PositionX = element.X,
                        PositionY = element.Y,
                        Width = element.Width,
                        Height = element.Height,
                        AdditionalStyles = element.AdditionalStyles
                    });
                }
                
                await _templateService.CreateTemplateAsync(CurrentTemplate);
                
                // Serialize the elements
                var elements = CurrentTemplate.Elements.Select(e => new
                {
                    id = e.ElementId,
                    type = e.ElementType,
                    text = e.Text,
                    x = e.PositionX,
                    y = e.PositionY,
                    width = e.Width,
                    height = e.Height,
                    color = e.Color,
                    additionalStyles = e.AdditionalStyles,
                    imageUrl = e.ImageUrl,
                    imageDescription = e.ImageDescription,
                    required = true,
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
                    }).ToList(),
                    // Add product-related properties
                    isProduct = e.IsProduct,
                    productName = e.ProductName,
                    productDescription = e.ProductDescription,
                    productPrice = e.ProductPrice,
                    productStockQuantity = e.ProductStockQuantity,
                    isAvailable = e.IsAvailable,
                    // Add the database ID
                    dbId = e.Id,
                    ingredients = e.Ingredients.Select(ing => new {
                        ingredientName = ing.IngredientName,
                        quantity = ing.Quantity,
                        unit = ing.Unit,
                        notes = ing.Notes
                    }).ToList()
                }).ToList();
                
                TemplateElementsJson = JsonSerializer.Serialize(elements);
            }
            else if (CurrentPage == "AssistantManagerDashboard")
            {
                // For Assistant Manager Dashboard, create a new template with required components
                CurrentTemplate = new PageTemplate
                {
                    Name = CurrentPage,
                    Description = $"Template for {CurrentPage}",
                    BackgroundColor = "#ffffff",
                    CreatedAt = DateTime.Now
                };
                
                foreach (var element in DefaultAssistantManagerDashboardElements)
                {
                    CurrentTemplate.Elements.Add(new PageElement
                    {
                        PageName = CurrentPage,
                        ElementType = element.Type,
                        ElementId = element.Id,
                        Text = element.Text,
                        Color = element.Color,
                        PositionX = element.X,
                        PositionY = element.Y,
                        Width = element.Width,
                        Height = element.Height,
                        AdditionalStyles = element.AdditionalStyles
                    });
                }
                
                await _templateService.CreateTemplateAsync(CurrentTemplate);
                
                // Serialize the elements
                var elements = CurrentTemplate.Elements.Select(e => new
                {
                    id = e.ElementId,
                    type = e.ElementType,
                    text = e.Text,
                    x = e.PositionX,
                    y = e.PositionY,
                    width = e.Width,
                    height = e.Height,
                    color = e.Color,
                    additionalStyles = e.AdditionalStyles,
                    imageUrl = e.ImageUrl,
                    imageDescription = e.ImageDescription,
                    required = true,
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
                    }).ToList(),
                    // Add product-related properties
                    isProduct = e.IsProduct,
                    productName = e.ProductName,
                    productDescription = e.ProductDescription,
                    productPrice = e.ProductPrice,
                    productStockQuantity = e.ProductStockQuantity,
                    isAvailable = e.IsAvailable,
                    // Add the database ID
                    dbId = e.Id,
                    ingredients = e.Ingredients.Select(ing => new {
                        ingredientName = ing.IngredientName,
                        quantity = ing.Quantity,
                        unit = ing.Unit,
                        notes = ing.Notes
                    }).ToList()
                }).ToList();
                
                TemplateElementsJson = JsonSerializer.Serialize(elements);
            }
            else if (CurrentPage == "InventoryClerkDashboard")
            {
                // For Inventory Clerk Dashboard, create a new template with required components
                CurrentTemplate = new PageTemplate
                {
                    Name = CurrentPage,
                    Description = $"Template for {CurrentPage}",
                    BackgroundColor = "#f5f5f5",
                    CreatedAt = DateTime.Now
                };
                
                foreach (var element in DefaultInventoryClerkDashboardElements)
                {
                    CurrentTemplate.Elements.Add(new PageElement
                    {
                        PageName = CurrentPage,
                        ElementType = element.Type,
                        ElementId = element.Id,
                        Text = element.Text,
                        Color = element.Color,
                        PositionX = element.X,
                        PositionY = element.Y,
                        Width = element.Width,
                        Height = element.Height,
                        AdditionalStyles = element.AdditionalStyles
                    });
                }
                
                await _templateService.CreateTemplateAsync(CurrentTemplate);
                
                // Serialize the elements
                var elements = CurrentTemplate.Elements.Select(e => new
                {
                    id = e.ElementId,
                    type = e.ElementType,
                    text = e.Text,
                    x = e.PositionX,
                    y = e.PositionY,
                    width = e.Width,
                    height = e.Height,
                    color = e.Color,
                    additionalStyles = e.AdditionalStyles,
                    imageUrl = e.ImageUrl,
                    imageDescription = e.ImageDescription,
                    required = true,
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
                    }).ToList(),
                    // Add product-related properties
                    isProduct = e.IsProduct,
                    productName = e.ProductName,
                    productDescription = e.ProductDescription,
                    productPrice = e.ProductPrice,
                    productStockQuantity = e.ProductStockQuantity,
                    isAvailable = e.IsAvailable,
                    // Add the database ID
                    dbId = e.Id,
                    ingredients = e.Ingredients.Select(ing => new {
                        ingredientName = ing.IngredientName,
                        quantity = ing.Quantity,
                        unit = ing.Unit,
                        notes = ing.Notes
                    }).ToList()
                }).ToList();
                
                TemplateElementsJson = JsonSerializer.Serialize(elements);
            }
            else if (CurrentPage == "Dashboard")
            {
                // For User Dashboard, create a new template with required components
                CurrentTemplate = new PageTemplate
                {
                    Name = CurrentPage,
                    Description = $"Template for {CurrentPage}",
                    BackgroundColor = "#ffffff",
                    CreatedAt = DateTime.Now
                };
                
                foreach (var element in DefaultDashboardElements)
                {
                    CurrentTemplate.Elements.Add(new PageElement
                    {
                        PageName = CurrentPage,
                        ElementType = element.Type,
                        ElementId = element.Id,
                        Text = element.Text,
                        Color = element.Color,
                        PositionX = element.X,
                        PositionY = element.Y,
                        Width = element.Width,
                        Height = element.Height,
                        AdditionalStyles = element.AdditionalStyles
                    });
                }
                
                await _templateService.CreateTemplateAsync(CurrentTemplate);
                
                // Serialize the elements
                var elements = CurrentTemplate.Elements.Select(e => new
                {
                    id = e.ElementId,
                    type = e.ElementType,
                    text = e.Text,
                    x = e.PositionX,
                    y = e.PositionY,
                    width = e.Width,
                    height = e.Height,
                    color = e.Color,
                    additionalStyles = e.AdditionalStyles,
                    imageUrl = e.ImageUrl,
                    imageDescription = e.ImageDescription,
                    required = DefaultDashboardElements.Any(d => d.Id == e.ElementId),
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
                    }).ToList(),
                    // Add product-related properties
                    isProduct = e.IsProduct,
                    productName = e.ProductName,
                    productDescription = e.ProductDescription,
                    productPrice = e.ProductPrice,
                    productStockQuantity = e.ProductStockQuantity,
                    isAvailable = e.IsAvailable,
                    // Add the database ID
                    dbId = e.Id,
                    ingredients = e.Ingredients.Select(ing => new {
                        ingredientName = ing.IngredientName,
                        quantity = ing.Quantity,
                        unit = ing.Unit,
                        notes = ing.Notes
                    }).ToList()
                }).ToList();
                
                TemplateElementsJson = JsonSerializer.Serialize(elements);
            }
            else if (CurrentPage == "MyOrders")
            {
                // For My Orders page, create a new template with required components
                CurrentTemplate = new PageTemplate
                {
                    Name = CurrentPage,
                    Description = $"Template for {CurrentPage}",
                    BackgroundColor = "#ffffff",
                    CreatedAt = DateTime.Now
                };
                
                // Check if the default elements are populated
                if (DefaultMyOrdersElements == null || !DefaultMyOrdersElements.Any())
                {
                    // If not, use a local variable instead of reassigning the readonly field
                    var myOrdersElements = new List<ElementModel>
                    {
                        // Header section
                        new ElementModel { Id = "welcome-label", Type = "Label", Text = "My Orders", X = 20, Y = 20, Width = 400, Height = 40, Color = "#343a40" },
                        
                        // Orders table panel
                        new ElementModel { Id = "orders-table", Type = "ContentPanel", Text = "Orders", X = 20, Y = 80, Width = 940, Height = 400, Color = "#f8f9fa", 
                            AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); overflow-y: auto; overflow-x: hidden; max-height: 400px; display: block;" },
                        
                        // Back to Dashboard button
                        new ElementModel { Id = "back-button", Type = "Button", Text = "Back to Dashboard", X = 20, Y = 500, Width = 200, Height = 40, Color = "#007bff" }
                    };
                    
                    // Use this local variable for adding elements
                    foreach (var element in myOrdersElements)
                    {
                        var pageElement = new PageElement
                        {
                            PageName = CurrentPage,
                            ElementType = element.Type,
                            ElementId = element.Id,
                            Text = element.Text,
                            Color = element.Color,
                            PositionX = element.X,
                            PositionY = element.Y,
                            Width = element.Width,
                            Height = element.Height,
                            AdditionalStyles = element.AdditionalStyles
                        };
                        
                        CurrentTemplate.Elements.Add(pageElement);
                    }
                }
                else
                {
                    // Add all default elements to the template
                    foreach (var element in DefaultMyOrdersElements)
                    {
                        var pageElement = new PageElement
                        {
                            PageName = CurrentPage,
                            ElementType = element.Type,
                            ElementId = element.Id,
                            Text = element.Text,
                            Color = element.Color,
                            PositionX = element.X,
                            PositionY = element.Y,
                            Width = element.Width,
                            Height = element.Height,
                            AdditionalStyles = element.AdditionalStyles
                        };
                        
                        CurrentTemplate.Elements.Add(pageElement);
                    }
                }
                
                await _templateService.CreateTemplateAsync(CurrentTemplate);
                
                // Serialize the elements
                var elements = CurrentTemplate.Elements.Select(e => new
                {
                    id = e.ElementId,
                    type = e.ElementType,
                    text = e.Text,
                    x = e.PositionX,
                    y = e.PositionY,
                    width = e.Width,
                    height = e.Height,
                    color = e.Color,
                    additionalStyles = e.AdditionalStyles,
                    imageUrl = e.ImageUrl,
                    imageDescription = e.ImageDescription,
                    required = DefaultMyOrdersElements.Any(d => d.Id == e.ElementId),
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
                    }).ToList(),
                    // Add product-related properties
                    isProduct = e.IsProduct,
                    productName = e.ProductName,
                    productDescription = e.ProductDescription,
                    productPrice = e.ProductPrice,
                    productStockQuantity = e.ProductStockQuantity,
                    isAvailable = e.IsAvailable,
                    // Add the database ID
                    dbId = e.Id,
                    ingredients = e.Ingredients.Select(ing => new {
                        ingredientName = ing.IngredientName,
                        quantity = ing.Quantity,
                        unit = ing.Unit,
                        notes = ing.Notes
                    }).ToList()
                }).ToList();
                
                TemplateElementsJson = JsonSerializer.Serialize(elements);
            }
            else
            {
                // If no template exists for other pages, we'll use empty defaults
                TemplateElementsJson = "[]";
            }
            
            return Page();
        }
        
        // Ensure Register page has all required fields
        private void EnsureRegisterPageFields()
        {
            if (CurrentTemplate == null) return;
            
            // Get IDs of current elements
            var currentElementIds = CurrentTemplate.Elements.Select(e => e.ElementId).ToList();
            
            // Find missing required elements
            var missingElements = DefaultRegisterElements
                .Where(de => !currentElementIds.Contains(de.Id))
                .ToList();
            
            // Add any missing elements
            foreach (var element in missingElements)
            {
                CurrentTemplate.Elements.Add(new PageElement
                {
                    PageName = CurrentPage,
                    ElementType = element.Type,
                    ElementId = element.Id,
                    Text = element.Text,
                    Color = element.Color,
                    PositionX = element.X,
                    PositionY = element.Y,
                    Width = element.Width,
                    Height = element.Height
                });
            }
            
            // Update the template if elements were added
            if (missingElements.Any())
            {
                _templateService.UpdateTemplateAsync(CurrentTemplate).Wait();
            }
        }
        
        // Ensure Cashier Dashboard has all required components
        private void EnsureEmployeeDashboardComponents()
        {
            if (CurrentTemplate == null) return;
            
            // Get IDs of current elements
            var currentElementIds = CurrentTemplate.Elements.Select(e => e.ElementId).ToList();
            
            // Find missing required elements
            var missingElements = DefaultEmployeeDashboardElements
                .Where(de => !currentElementIds.Contains(de.Id))
                .ToList();
            
            // Add any missing elements
            foreach (var element in missingElements)
            {
                CurrentTemplate.Elements.Add(new PageElement
                {
                    PageName = CurrentPage,
                    ElementType = element.Type,
                    ElementId = element.Id,
                    Text = element.Text,
                    Color = element.Color,
                    PositionX = element.X,
                    PositionY = element.Y,
                    Width = element.Width,
                    Height = element.Height,
                    AdditionalStyles = element.AdditionalStyles
                });
            }
            
            // Update the template if elements were added
            if (missingElements.Any())
            {
                _templateService.UpdateTemplateAsync(CurrentTemplate).Wait();
            }
        }
        
        // Ensure Manager Dashboard has all required components
        private void EnsureManagerDashboardComponents()
        {
            if (CurrentTemplate == null) return;
            
            // Get IDs of current elements
            var currentElementIds = CurrentTemplate.Elements.Select(e => e.ElementId).ToList();
            
            // Find missing required elements
            var missingElements = DefaultManagerDashboardElements
                .Where(de => !currentElementIds.Contains(de.Id))
                .ToList();
            
            // Add any missing elements
            foreach (var element in missingElements)
            {
                CurrentTemplate.Elements.Add(new PageElement
                {
                    PageName = CurrentPage,
                    ElementType = element.Type,
                    ElementId = element.Id,
                    Text = element.Text,
                    Color = element.Color,
                    PositionX = element.X,
                    PositionY = element.Y,
                    Width = element.Width,
                    Height = element.Height,
                    AdditionalStyles = element.AdditionalStyles
                });
            }
            
            // Update the template if elements were added
            if (missingElements.Any())
            {
                _templateService.UpdateTemplateAsync(CurrentTemplate).Wait();
            }
        }
        
        // Ensure Assistant Manager Dashboard has all required components
        private void EnsureAssistantManagerDashboardComponents()
        {
            if (CurrentTemplate == null) return;
            
            // Get IDs of current elements
            var currentElementIds = CurrentTemplate.Elements.Select(e => e.ElementId).ToList();
            
            // Find missing required elements
            var missingElements = DefaultAssistantManagerDashboardElements
                .Where(de => !currentElementIds.Contains(de.Id))
                .ToList();
            
            // Add any missing elements
            foreach (var element in missingElements)
            {
                CurrentTemplate.Elements.Add(new PageElement
                {
                    PageName = CurrentPage,
                    ElementType = element.Type,
                    ElementId = element.Id,
                    Text = element.Text,
                    Color = element.Color,
                    PositionX = element.X,
                    PositionY = element.Y,
                    Width = element.Width,
                    Height = element.Height,
                    AdditionalStyles = element.AdditionalStyles
                });
            }
            
            // Update existing elements to match default
            foreach (var defaultElement in DefaultAssistantManagerDashboardElements)
            {
                var existingElement = CurrentTemplate.Elements.FirstOrDefault(e => e.ElementId == defaultElement.Id);
                if (existingElement != null)
                {
                    // Update the element to match the default
                    existingElement.Text = defaultElement.Text;
                    existingElement.ElementType = defaultElement.Type;
                    existingElement.Color = defaultElement.Color;
                    existingElement.PositionX = defaultElement.X;
                    existingElement.PositionY = defaultElement.Y;
                    existingElement.Width = defaultElement.Width;
                    existingElement.Height = defaultElement.Height;
                    existingElement.AdditionalStyles = defaultElement.AdditionalStyles;
                }
            }
            
            // Update the background color
            CurrentTemplate.BackgroundColor = "#ffffff";
            
            // Update the template if elements were added or modified
            _templateService.UpdateTemplateAsync(CurrentTemplate).Wait();
        }
        
        // Ensure Inventory Clerk Dashboard has all required components
        private void EnsureInventoryClerkDashboardComponents()
        {
            if (CurrentTemplate == null) return;
            
            // Get IDs of current elements
            var currentElementIds = CurrentTemplate.Elements.Select(e => e.ElementId).ToList();
            
            // Find missing required elements
            var missingElements = DefaultInventoryClerkDashboardElements
                .Where(de => !currentElementIds.Contains(de.Id))
                .ToList();
            
            // Add any missing elements
            foreach (var element in missingElements)
            {
                CurrentTemplate.Elements.Add(new PageElement
                {
                    PageName = CurrentPage,
                    ElementType = element.Type,
                    ElementId = element.Id,
                    Text = element.Text,
                    Color = element.Color,
                    PositionX = element.X,
                    PositionY = element.Y,
                    Width = element.Width,
                    Height = element.Height,
                    AdditionalStyles = element.AdditionalStyles
                });
            }
            
            // Update the template if elements were added
            if (missingElements.Any())
            {
                _templateService.UpdateTemplateAsync(CurrentTemplate).Wait();
            }
        }
        
        // Ensure User Dashboard has all required components
        private void EnsureDashboardComponents()
        {
            if (CurrentTemplate == null) return;
            
            // Get IDs of current elements
            var currentElementIds = CurrentTemplate.Elements.Select(e => e.ElementId).ToList();
            
            // Find missing required elements
            var missingElements = DefaultDashboardElements
                .Where(de => !currentElementIds.Contains(de.Id))
                .ToList();
            
            // Add any missing elements
            foreach (var element in missingElements)
            {
                CurrentTemplate.Elements.Add(new PageElement
                {
                    PageName = CurrentPage,
                    ElementType = element.Type,
                    ElementId = element.Id,
                    Text = element.Text,
                    Color = element.Color,
                    PositionX = element.X,
                    PositionY = element.Y,
                    Width = element.Width,
                    Height = element.Height,
                    AdditionalStyles = element.AdditionalStyles
                });
            }
            
            // Update the template if elements were added
            if (missingElements.Any())
            {
                _templateService.UpdateTemplateAsync(CurrentTemplate).Wait();
            }
        }

        // Ensure My Orders page has all required components
        private void EnsureMyOrdersComponents()
        {
            if (CurrentTemplate == null) return;
            
            // Get IDs of current elements
            var currentElementIds = CurrentTemplate.Elements.Select(e => e.ElementId).ToList();
            
            // Find missing required elements
            var missingElements = DefaultMyOrdersElements
                .Where(de => !currentElementIds.Contains(de.Id))
                .ToList();
            
            // Add any missing elements
            foreach (var element in missingElements)
            {
                CurrentTemplate.Elements.Add(new PageElement
                {
                    PageName = CurrentPage,
                    ElementType = element.Type,
                    ElementId = element.Id,
                    Text = element.Text,
                    Color = element.Color,
                    PositionX = element.X,
                    PositionY = element.Y,
                    Width = element.Width,
                    Height = element.Height,
                    AdditionalStyles = element.AdditionalStyles
                });
            }
            
            // Update the template if elements were added
            if (missingElements.Any())
            {
                _templateService.UpdateTemplateAsync(CurrentTemplate).Wait();
            }
        }

        public async Task<IActionResult> OnPostSaveTemplateAsync([FromBody] TemplateUpdateModel model)
        {
            if (model == null)
            {
                return BadRequest("Invalid template data");
            }

            // Log products and their availability status
            var products = model.Elements.Where(e => e.Type == "Image" && e.IsProduct).ToList();
            System.Diagnostics.Debug.WriteLine($"Found {products.Count} products in template data");
            foreach (var product in products)
            {
                // Sanitize product names here first before logging
                product.ProductName = SqlInputSanitizer.SanitizeString(product.ProductName ?? string.Empty);
                product.ProductDescription = SqlInputSanitizer.SanitizeString(product.ProductDescription ?? string.Empty);
                
                // Sanitize each ingredient if any
                if (product.Ingredients != null)
                {
                    foreach (var ingredient in product.Ingredients)
                    {
                        if (ingredient != null)
                        {
                            ingredient.IngredientName = SqlInputSanitizer.SanitizeString(ingredient.IngredientName ?? string.Empty);
                            ingredient.Unit = SqlInputSanitizer.SanitizeString(ingredient.Unit ?? string.Empty);
                            ingredient.Notes = SqlInputSanitizer.SanitizeString(ingredient.Notes ?? string.Empty);
                        }
                    }
                }
                
                System.Diagnostics.Debug.WriteLine($"Product {product.ProductName} (ID: {product.Id}): IsAvailable = {product.IsAvailable}");
            }

            // For Register page, ensure all required fields are present
            if (model.PageName == "Register")
            {
                var requiredFieldIds = DefaultRegisterElements.Select(e => e.Id).ToList();
                var modelFieldIds = model.Elements.Select(e => e.Id).ToList();
                
                if (requiredFieldIds.Except(modelFieldIds).Any())
                {
                    return BadRequest("Register page template is missing required fields");
                }
            }
            
            // For Cashier Dashboard, ensure all required components are present
            if (model.PageName == "EmployeeDashboard")
            {
                var requiredComponentIds = DefaultEmployeeDashboardElements.Select(e => e.Id).ToList();
                var modelComponentIds = model.Elements.Select(e => e.Id).ToList();
                
                if (!requiredComponentIds.All(id => model.Elements.Any(e => e.Id == id)))
                {
                    return BadRequest("Cashier Dashboard template is missing required components");
                }
            }
            
            // For User Dashboard, ensure all required components are present
            if (model.PageName == "Dashboard")
            {
                var requiredComponentIds = DefaultDashboardElements.Select(e => e.Id).ToList();
                var modelComponentIds = model.Elements.Select(e => e.Id).ToList();
                
                if (requiredComponentIds.Except(modelComponentIds).Any())
                {
                    return BadRequest("User Dashboard template is missing required components");
                }
            }

            // Find or create the template
            var template = await _templateService.GetTemplateByNameAsync(model.PageName);
            if (template == null)
            {
                template = new PageTemplate
                {
                    Name = model.PageName,
                    Description = $"Template for {model.PageName} page",
                    BackgroundColor = model.BackgroundColor ?? "#ffffff",
                    CreatedAt = DateTime.Now
                };
            }
            else
            {
                template.BackgroundColor = model.BackgroundColor ?? template.BackgroundColor;
            }

            // Clear existing elements
            template.Elements.Clear();

            // Add updated elements
            foreach (var elem in model.Elements)
            {
                var element = new PageElement
                {
                    PageName = model.PageName,
                    ElementType = elem.Type,
                    ElementId = elem.Id,
                    Text = SqlInputSanitizer.SanitizeString(elem.Text ?? string.Empty),
                    Color = SqlInputSanitizer.SanitizeString(elem.Color ?? string.Empty),
                    PositionX = elem.X,
                    PositionY = elem.Y,
                    Width = elem.Width,
                    Height = elem.Height,
                    AdditionalStyles = SqlInputSanitizer.SanitizeString(elem.AdditionalStyles ?? string.Empty),
                    LastModified = DateTime.Now
                };

                // Handle image properties
                if (elem.Type == "Image")
                {
                    element.ImageUrl = elem.ImageUrl ?? string.Empty;
                    element.ImageDescription = elem.ImageDescription ?? string.Empty;
                    
                    // Initialize images collection if needed
                    if (element.Images == null)
                    {
                        element.Images = new List<PageElementImage>();
                    }
                    
                    // Handle multiple images with null check
                    if (elem.Images != null)
                    {
                        foreach (var img in elem.Images)
                        {
                            if (img != null)
                            {
                                element.Images.Add(new PageElementImage
                                {
                                    Base64Data = img.Base64Data ?? string.Empty,
                                    Description = img.Description ?? string.Empty
                                });
                            }
                        }
                    }
                    
                    // Handle product-related properties
                    if (elem.IsProduct)
                    {
                        element.IsProduct = true;
                        // Double-ensure sanitization here
                        element.ProductName = SqlInputSanitizer.SanitizeString(elem.ProductName ?? string.Empty);
                        element.ProductDescription = SqlInputSanitizer.SanitizeString(elem.ProductDescription ?? string.Empty);
                        element.ProductPrice = elem.ProductPrice;
                        element.ProductStockQuantity = elem.ProductStockQuantity;
                        element.IsAvailable = elem.IsAvailable;
                        
                        // Log for debugging
                        System.Diagnostics.Debug.WriteLine($"After sanitization - Saving product: {element.ProductName}");
                        
                        // Initialize ingredients collection if needed
                        if (element.Ingredients == null)
                        {
                            element.Ingredients = new List<ProductIngredient>();
                        }
                        
                        // Handle ingredients with null check
                        if (elem.Ingredients != null)
                        {
                            foreach (var ingredient in elem.Ingredients)
                            {
                                if (ingredient != null)
                                {
                                    var productIngredient = new ProductIngredient
                                    {
                                        IngredientName = SqlInputSanitizer.SanitizeString(ingredient.IngredientName ?? string.Empty),
                                        Quantity = ingredient.Quantity,
                                        Unit = SqlInputSanitizer.SanitizeString(ingredient.Unit ?? string.Empty),
                                        Notes = SqlInputSanitizer.SanitizeString(ingredient.Notes ?? string.Empty)
                                    };
                                    
                                    element.Ingredients.Add(productIngredient);
                                }
                            }
                        }
                    }
                }

                template.Elements.Add(element);
            }

            // Save the updated template
            await _templateService.UpdateTemplateAsync(template);

            return new OkResult();
        }

        public async Task<IActionResult> OnPostResetToDefault()
        {
            // Load the current template
            CurrentTemplate = await _templateService.GetTemplateByNameAsync(CurrentPage);
            
            if (CurrentTemplate != null)
            {
                if (CurrentPage == "ManagerDashboard")
                {
                    // Reset to default Manager Dashboard
                    CurrentTemplate.Elements.Clear();
                    
                    foreach (var element in DefaultManagerDashboardElements)
                    {
                        CurrentTemplate.Elements.Add(new PageElement
                        {
                            PageName = CurrentPage,
                            ElementType = element.Type,
                            ElementId = element.Id,
                            Text = element.Text,
                            Color = element.Color,
                            PositionX = element.X,
                            PositionY = element.Y,
                            Width = element.Width,
                            Height = element.Height,
                            AdditionalStyles = element.AdditionalStyles
                        });
                    }
                    
                    // Set the background color
                    CurrentTemplate.BackgroundColor = "#ffffff";
                    
                    // Save the changes
                    await _templateService.UpdateTemplateAsync(CurrentTemplate);
                }
                else if (CurrentPage == "AssistantManagerDashboard")
                {
                    // Reset to default Assistant Manager Dashboard
                    CurrentTemplate.Elements.Clear();
                    
                    foreach (var element in DefaultAssistantManagerDashboardElements)
                    {
                        CurrentTemplate.Elements.Add(new PageElement
                        {
                            PageName = CurrentPage,
                            ElementType = element.Type,
                            ElementId = element.Id,
                            Text = element.Text,
                            Color = element.Color,
                            PositionX = element.X,
                            PositionY = element.Y,
                            Width = element.Width,
                            Height = element.Height,
                            AdditionalStyles = element.AdditionalStyles
                        });
                    }
                    
                    // Set the background color
                    CurrentTemplate.BackgroundColor = "#ffffff";
                    
                    // Save the changes
                    await _templateService.UpdateTemplateAsync(CurrentTemplate);
                }
                else if (CurrentPage == "MyOrders")
                {
                    try
                    {
                        // Reset to default My Orders page
                        CurrentTemplate.Elements.Clear();
                        
                        // Check if the default elements are populated
                        if (DefaultMyOrdersElements == null || !DefaultMyOrdersElements.Any())
                        {
                            // If not, use a local variable instead of reassigning the readonly field
                            var myOrdersElements = new List<ElementModel>
                            {
                                // Header section
                                new ElementModel { Id = "welcome-label", Type = "Label", Text = "My Orders", X = 20, Y = 20, Width = 400, Height = 40, Color = "#343a40" },
                                
                                // Orders table panel
                                new ElementModel { Id = "orders-table", Type = "ContentPanel", Text = "Orders", X = 20, Y = 80, Width = 940, Height = 400, Color = "#f8f9fa", 
                                    AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); overflow-y: auto; overflow-x: hidden; max-height: 400px; display: block;" },
                                
                                // Back to Dashboard button
                                new ElementModel { Id = "back-button", Type = "Button", Text = "Back to Dashboard", X = 20, Y = 500, Width = 200, Height = 40, Color = "#007bff" }
                            };
                            
                            // Use this local variable for adding elements
                            foreach (var element in myOrdersElements)
                            {
                                var pageElement = new PageElement
                                {
                                    PageName = CurrentPage,
                                    ElementType = element.Type,
                                    ElementId = element.Id,
                                    Text = element.Text,
                                    Color = element.Color,
                                    PositionX = element.X,
                                    PositionY = element.Y,
                                    Width = element.Width,
                                    Height = element.Height,
                                    AdditionalStyles = element.AdditionalStyles
                                };
                                
                                CurrentTemplate.Elements.Add(pageElement);
                            }
                        }
                        else
                        {
                            // Add all default elements to the template
                            foreach (var element in DefaultMyOrdersElements)
                            {
                                var pageElement = new PageElement
                                {
                                    PageName = CurrentPage,
                                    ElementType = element.Type,
                                    ElementId = element.Id,
                                    Text = element.Text,
                                    Color = element.Color,
                                    PositionX = element.X,
                                    PositionY = element.Y,
                                    Width = element.Width,
                                    Height = element.Height,
                                    AdditionalStyles = element.AdditionalStyles
                                };
                                
                                CurrentTemplate.Elements.Add(pageElement);
                            }
                        }
                        
                        // Set the background color
                        CurrentTemplate.BackgroundColor = "#ffffff";
                        
                        // Save the changes
                        await _templateService.UpdateTemplateAsync(CurrentTemplate);
                        
                        // Refresh template data
                        CurrentTemplate = await _templateService.GetTemplateByNameAsync(CurrentPage);
                        
                        // Just a safety check to ensure elements were added
                        if (CurrentTemplate == null || !CurrentTemplate.Elements.Any())
                        {
                            TempData["ErrorMessage"] = "Failed to reset MyOrders template. No elements were added.";
                        }
                        else
                        {
                            TempData["SuccessMessage"] = $"Successfully reset MyOrders template with {CurrentTemplate.Elements.Count} elements.";
                        }
                    }
                    catch (Exception ex)
                    {
                        TempData["ErrorMessage"] = $"Error resetting MyOrders template: {ex.Message}";
                    }
                }
                // Other page reset logic...
            }
            
            // Reload template data for the view
            await OnGetAsync();
            
            // Redirect back to the page editor with the current page
            return RedirectToPage(new { CurrentPage = CurrentPage });
        }
    }

    // Helper class to deserialize the JSON data
    public class TemplateUpdateModel
    {
        private string _pageName;
        public string PageName
        {
            get => _pageName;
            set => _pageName = SqlInputSanitizer.SanitizeString(value);
        }
        
        private string _backgroundColor;
        public string BackgroundColor
        {
            get => _backgroundColor;
            set => _backgroundColor = SqlInputSanitizer.SanitizeString(value);
        }
        
        public List<ElementModel> Elements { get; set; }
    }

    public class ElementModel
    {
        private string _id;
        public string Id
        {
            get => _id;
            set => _id = SqlInputSanitizer.SanitizeString(value);
        }
        
        private string _type;
        public string Type
        {
            get => _type;
            set => _type = SqlInputSanitizer.SanitizeString(value);
        }
        
        private string _text;
        public string Text
        {
            get => _text;
            set => _text = SqlInputSanitizer.SanitizeString(value);
        }
        
        public int X { get; set; }
        public int Y { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        
        private string _color;
        public string Color
        {
            get => _color;
            set => _color = SqlInputSanitizer.SanitizeString(value);
        }
        
        private string _additionalStyles;
        public string AdditionalStyles
        {
            get => _additionalStyles;
            set => _additionalStyles = SqlInputSanitizer.SanitizeString(value);
        }
        
        private string _imageUrl;
        public string ImageUrl
        {
            get => _imageUrl;
            set => _imageUrl = SqlInputSanitizer.SanitizeString(value);
        }
        
        private string _imageDescription;
        public string ImageDescription
        {
            get => _imageDescription;
            set => _imageDescription = SqlInputSanitizer.SanitizeString(value);
        }
        
        public List<ImageModel> Images { get; set; } = new List<ImageModel>();
        
        // Product-related properties
        public bool IsProduct { get; set; }
        
        private string _productName;
        public string ProductName
        {
            get => _productName;
            set => _productName = SqlInputSanitizer.SanitizeString(value);
        }
        
        private string _productDescription;
        public string ProductDescription
        {
            get => _productDescription;
            set => _productDescription = SqlInputSanitizer.SanitizeString(value);
        }
        
        public decimal ProductPrice { get; set; }
        public int ProductStockQuantity { get; set; }
        public bool IsAvailable { get; set; } = true;
        public List<IngredientModel> Ingredients { get; set; } = new List<IngredientModel>();
    }
    
    public class ImageModel
    {
        private string _base64Data;
        public string Base64Data
        {
            get => _base64Data;
            set => _base64Data = value; // Don't sanitize binary data
        }
        
        private string _description;
        public string Description
        {
            get => _description;
            set => _description = SqlInputSanitizer.SanitizeString(value);
        }
    }
    
    public class IngredientModel
    {
        private string _ingredientName;
        public string IngredientName
        {
            get => _ingredientName;
            set => _ingredientName = SqlInputSanitizer.SanitizeString(value);
        }
        
        public decimal Quantity { get; set; }
        
        private string _unit;
        public string Unit
        {
            get => _unit;
            set => _unit = SqlInputSanitizer.SanitizeString(value);
        }
        
        private string _notes;
        public string Notes
        {
            get => _notes;
            set => _notes = SqlInputSanitizer.SanitizeString(value);
        }
    }
} 