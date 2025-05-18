using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Antiforgery;
using POS.Models;
using POS.Services;
using System.Text.Json;

namespace POS.Pages.api.templates
{
    [IgnoreAntiforgeryToken] // Add this to ignore anti-forgery validation for API
    public class SaveModel : PageModel
    {
        private readonly IPageTemplateService _templateService;

        public SaveModel(IPageTemplateService templateService)
        {
            _templateService = templateService;
        }

        [BindProperty]
        public TemplateUpdateModel Input { get; set; }

        public bool Success { get; private set; }
        public string Message { get; private set; }

        public async Task<IActionResult> OnPostAsync()
        {
            try
            {
                // Read request body directly since model binding might be failing
                using var reader = new StreamReader(Request.Body);
                var body = await reader.ReadToEndAsync();
                
                // Deserialize manually
                var input = JsonSerializer.Deserialize<TemplateUpdateModel>(body, 
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                
                if (input == null || string.IsNullOrEmpty(input.PageName) || input.Elements == null)
                {
                    Success = false;
                    Message = "Invalid template data - missing required fields";
                    return Page();
                }

                // Sanitize the input
                input.PageName = SqlInputSanitizer.SanitizeString(input.PageName);
                input.BackgroundColor = SqlInputSanitizer.SanitizeString(input.BackgroundColor ?? "#FFFFFF");
                
                // Sanitize each element
                foreach (var element in input.Elements)
                {
                    element.Id = SqlInputSanitizer.SanitizeString(element.Id);
                    element.Type = SqlInputSanitizer.SanitizeString(element.Type);
                    element.Text = SqlInputSanitizer.SanitizeString(element.Text);
                    element.Color = SqlInputSanitizer.SanitizeString(element.Color);
                    element.AdditionalStyles = SqlInputSanitizer.SanitizeString(element.AdditionalStyles);
                    element.ImageUrl = SqlInputSanitizer.SanitizeString(element.ImageUrl);
                    element.ImageDescription = SqlInputSanitizer.SanitizeString(element.ImageDescription);
                    
                    if (element.IsProduct)
                    {
                        element.ProductName = SqlInputSanitizer.SanitizeString(element.ProductName);
                        element.ProductDescription = SqlInputSanitizer.SanitizeString(element.ProductDescription);
                        
                        // Sanitize ingredients
                        if (element.Ingredients != null)
                        {
                            foreach (var ingredient in element.Ingredients)
                            {
                                ingredient.IngredientName = SqlInputSanitizer.SanitizeString(ingredient.IngredientName);
                                ingredient.Unit = SqlInputSanitizer.SanitizeString(ingredient.Unit);
                                ingredient.Notes = SqlInputSanitizer.SanitizeString(ingredient.Notes);
                            }
                        }
                    }
                }

                // Find or create the template
                var template = await _templateService.GetTemplateByNameAsync(input.PageName);
                bool isNew = template == null;
                
                if (isNew)
                {
                    template = new PageTemplate
                    {
                        Name = input.PageName,
                        Description = $"Template for {input.PageName} page",
                        BackgroundColor = input.BackgroundColor,
                        CreatedAt = DateTime.Now
                    };
                }
                else
                {
                    template.BackgroundColor = input.BackgroundColor ?? template.BackgroundColor;
                    template.LastModified = DateTime.Now;
                    
                    // Clear existing elements
                    template.Elements.Clear();
                }

                // Add updated elements
                foreach (var element in input.Elements)
                {
                    var pageElement = new PageElement
                    {
                        PageName = input.PageName,
                        ElementType = element.Type,
                        ElementId = element.Id,
                        Text = element.Text,
                        Color = element.Color,
                        PositionX = element.X,
                        PositionY = element.Y,
                        Width = element.Width,
                        Height = element.Height,
                        AdditionalStyles = element.AdditionalStyles,
                        LastModified = DateTime.Now,
                        ImageUrl = element.ImageUrl ?? string.Empty,
                        ImageDescription = element.ImageDescription ?? string.Empty,
                        IsProduct = element.IsProduct,
                        ProductName = element.ProductName ?? string.Empty,
                        ProductDescription = element.ProductDescription ?? string.Empty,
                        ProductPrice = element.ProductPrice,
                        ProductStockQuantity = element.ProductStockQuantity,
                        IsAvailable = element.IsAvailable
                    };
                    
                    // Handle ingredients if this is a product element
                    if (element.IsProduct && element.Ingredients != null && element.Ingredients.Count > 0)
                    {
                        foreach (var ingredient in element.Ingredients)
                        {
                            var productIngredient = new ProductIngredient
                            {
                                IngredientName = ingredient.IngredientName,
                                Quantity = ingredient.Quantity,
                                Unit = ingredient.Unit ?? "g",
                                Notes = ingredient.Notes ?? string.Empty
                            };
                            
                            pageElement.Ingredients.Add(productIngredient);
                        }
                    }
                    
                    template.Elements.Add(pageElement);
                }

                // Save the template
                if (isNew)
                {
                    await _templateService.CreateTemplateAsync(template);
                }
                else
                {
                    await _templateService.UpdateTemplateAsync(template);
                }

                Success = true;
                Message = "Template saved successfully";
            }
            catch (Exception ex)
            {
                Success = false;
                Message = $"Error saving template: {ex.Message}";
            }

            return Page();
        }
    }

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
        public bool IsProduct { get; set; }
        public string ProductName { get; set; }
        public string ProductDescription { get; set; }
        public decimal ProductPrice { get; set; }
        public int ProductStockQuantity { get; set; }
        public bool IsAvailable { get; set; } = true;
        public List<IngredientModel> Ingredients { get; set; }
    }
    
    public class IngredientModel
    {
        public string IngredientName { get; set; }
        public decimal Quantity { get; set; }
        public string Unit { get; set; }
        public string Notes { get; set; }
    }
} 