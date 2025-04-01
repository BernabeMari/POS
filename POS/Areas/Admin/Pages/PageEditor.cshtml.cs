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
            new ElementModel { Id = "terms-checkbox", Type = "Checkbox", Text = "I agree to the Terms and Conditions", X = 100, Y = 400, Width = 300, Height = 30, Color = "#000000" },
            new ElementModel { Id = "register-button", Type = "Button", Text = "Create Account", X = 100, Y = 450, Width = 300, Height = 40, Color = "#28a745" },
            new ElementModel { Id = "login-link", Type = "Label", Text = "Already have an account? Login here", X = 100, Y = 510, Width = 300, Height = 20, Color = "#007bff" }
        };
        
        // Default elements for the Employee Dashboard template
        private readonly List<ElementModel> DefaultEmployeeDashboardElements = new List<ElementModel> 
        {
            // Header section
            new ElementModel { Id = "welcome-label", Type = "Label", Text = "Employee Dashboard", X = 20, Y = 20, Width = 400, Height = 40, Color = "#343a40" },
            new ElementModel { Id = "employee-status", Type = "Label", Text = "Logged in as Employee", X = 620, Y = 20, Width = 300, Height = 30, Color = "#6c757d" },
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
        
        // Default elements for the User Dashboard template
        private readonly List<ElementModel> DefaultDashboardElements = new List<ElementModel> 
        {
            // Header section - only logout button
            new ElementModel { Id = "logout-button", Type = "Button", Text = "Logout", X = 830, Y = 20, Width = 100, Height = 40, Color = "#dc3545" },
            
            // My Orders Panel - the main element
            new ElementModel { Id = "my-orders", Type = "ContentPanel", Text = "My Orders", X = 20, Y = 80, Width = 940, Height = 300, Color = "#f8f9fa", 
                AdditionalStyles = "border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);" }
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
                // For Employee Dashboard, ensure all required components are present
                else if (CurrentPage == "EmployeeDashboard")
                {
                    EnsureEmployeeDashboardComponents();
                }
                // For User Dashboard, ensure all required components are present
                else if (CurrentPage == "Dashboard")
                {
                    EnsureDashboardComponents();
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
                               (CurrentPage == "EmployeeDashboard" && DefaultEmployeeDashboardElements.Any(d => d.Id == e.ElementId)),
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
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
                    }).ToList()
                }).ToList();
                
                TemplateElementsJson = JsonSerializer.Serialize(elements);
            }
            else if (CurrentPage == "EmployeeDashboard")
            {
                // For Employee Dashboard, create a new template with required components
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
                    required = DefaultEmployeeDashboardElements.Any(d => d.Id == e.ElementId),
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
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
                    BackgroundColor = "#f8f9fa",
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
        
        // Ensure Employee Dashboard has all required components
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

        public async Task<IActionResult> OnPostSaveTemplateAsync([FromBody] TemplateUpdateModel model)
        {
            if (model == null)
            {
                return BadRequest("Invalid template data");
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
            
            // For Employee Dashboard, ensure all required components are present
            if (model.PageName == "EmployeeDashboard")
            {
                var requiredComponentIds = DefaultEmployeeDashboardElements.Select(e => e.Id).ToList();
                var modelComponentIds = model.Elements.Select(e => e.Id).ToList();
                
                if (requiredComponentIds.Except(modelComponentIds).Any())
                {
                    return BadRequest("Employee Dashboard template is missing required components");
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
                    Text = elem.Text,
                    Color = elem.Color,
                    PositionX = elem.X,
                    PositionY = elem.Y,
                    Width = elem.Width,
                    Height = elem.Height,
                    AdditionalStyles = elem.AdditionalStyles,
                    LastModified = DateTime.Now
                };

                // Handle image properties
                if (elem.Type == "Image")
                {
                    element.ImageUrl = elem.ImageUrl;
                    element.ImageDescription = elem.ImageDescription;
                    
                    // Handle multiple images
                    if (elem.Images != null && elem.Images.Count > 0)
                    {
                        foreach (var img in elem.Images)
                        {
                            element.Images.Add(new PageElementImage
                            {
                                Base64Data = img.Base64Data,
                                Description = img.Description
                            });
                        }
                    }
                }

                template.Elements.Add(element);
            }

            // Save the updated template
            await _templateService.UpdateTemplateAsync(template);

            return new OkResult();
        }
    }

    // Helper class to deserialize the JSON data
    public class TemplateUpdateModel
    {
        public string PageName { get; set; }
        public string BackgroundColor { get; set; }
        public List<ElementModel> Elements { get; set; }
    }

    public class ElementModel
    {
        public string Id { get; set; }
        public string Type { get; set; }
        public string Text { get; set; }
        public int X { get; set; }
        public int Y { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public string Color { get; set; }
        public string AdditionalStyles { get; set; }
        public string ImageUrl { get; set; }
        public string ImageDescription { get; set; }
        public List<ImageModel> Images { get; set; }
    }
    
    public class ImageModel
    {
        public string Base64Data { get; set; }
        public string Description { get; set; }
    }
} 