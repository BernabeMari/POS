using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Text.Json;

namespace POS.Pages.api.templates
{
    public class ActiveModel : PageModel
    {
        private readonly IPageTemplateService _templateService;
        private readonly IPageElementService _elementService;

        public ActiveModel(IPageTemplateService templateService, IPageElementService elementService)
        {
            _templateService = templateService;
            _elementService = elementService;
        }

        public object Template { get; private set; }

        public async Task<IActionResult> OnGetAsync(string pageName)
        {
            if (string.IsNullOrEmpty(pageName))
            {
                return BadRequest("Page name is required");
            }

            var template = await _templateService.GetTemplateByNameAsync(pageName);
            if (template == null)
            {
                // If no template exists, return default elements
                Template = CreateDefaultTemplate(pageName);
                return Page();
            }

            // Format the template in a way that's easier to use in JavaScript
            Template = new
            {
                id = template.Id,
                name = template.Name,
                backgroundColor = template.BackgroundColor,
                elements = template.Elements.Select(e => new
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
                    isVisible = e.IsVisible,
                    imageUrl = e.ImageUrl,
                    imageDescription = e.ImageDescription,
                    isProduct = e.IsProduct,
                    productName = e.ProductName,
                    productPrice = e.ProductPrice,
                    productDescription = e.ProductDescription,
                    productStockQuantity = e.ProductStockQuantity,
                    isAvailable = e.IsAvailable,
                    dbId = e.Id,
                    images = e.Images.Select(img => new {
                        base64Data = img.Base64Data,
                        description = img.Description
                    }).ToList(),
                    ingredients = e.Ingredients.Select(ing => new {
                        ingredientName = ing.IngredientName, 
                        quantity = ing.Quantity,
                        unit = ing.Unit
                    }).ToList()
                }).ToList()
            };

            return Page();
        }

        private object CreateDefaultTemplate(string pageName)
        {
            var elements = new List<object>();

            if (pageName.Equals("Login", StringComparison.OrdinalIgnoreCase))
            {
                elements.Add(new { id = "email-input", type = "InputField", text = "Email", x = 100, y = 100, width = 300, height = 40, color = "#000000" });
                elements.Add(new { id = "password-input", type = "InputField", text = "Password", x = 100, y = 160, width = 300, height = 40, color = "#000000" });
                elements.Add(new { id = "login-button", type = "Button", text = "Login", x = 100, y = 220, width = 300, height = 40, color = "#007bff" });
                elements.Add(new { id = "signup-link", type = "Label", text = "Don't have an account? Register here", x = 100, y = 280, width = 300, height = 20, color = "#007bff" });
            }
            else if (pageName.Equals("Register", StringComparison.OrdinalIgnoreCase))
            {
                elements.Add(new { id = "fullname-input", type = "InputField", text = "Full Name", x = 100, y = 100, width = 300, height = 40, color = "#000000" });
                elements.Add(new { id = "username-input", type = "InputField", text = "Username", x = 100, y = 160, width = 300, height = 40, color = "#000000" });
                elements.Add(new { id = "email-input", type = "InputField", text = "Email Address", x = 100, y = 220, width = 300, height = 40, color = "#000000" });
                elements.Add(new { id = "password-input", type = "InputField", text = "Password", x = 100, y = 280, width = 300, height = 40, color = "#000000" });
                elements.Add(new { id = "confirm-password", type = "InputField", text = "Confirm Password", x = 100, y = 340, width = 300, height = 40, color = "#000000" });
                elements.Add(new { id = "terms-checkbox", type = "Checkbox", text = "I agree to the Terms and Conditions", x = 100, y = 400, width = 300, height = 30, color = "#000000" });
                elements.Add(new { id = "register-button", type = "Button", text = "Create Account", x = 100, y = 450, width = 300, height = 40, color = "#28a745" });
                elements.Add(new { id = "login-link", type = "Label", text = "Already have an account? Login here", x = 100, y = 510, width = 300, height = 20, color = "#007bff" });
            }
            else if (pageName.Equals("Dashboard", StringComparison.OrdinalIgnoreCase))
            {
                elements.Add(new { id = "welcome-label", type = "Label", text = "Welcome to your Dashboard", x = 100, y = 50, width = 400, height = 30, color = "#343a40" });
                elements.Add(new { id = "logout-button", type = "Button", text = "Logout", x = 500, y = 50, width = 100, height = 40, color = "#dc3545" });
            }

            return new
            {
                name = pageName,
                backgroundColor = "#FFFFFF",
                elements = elements
            };
        }
    }
} 