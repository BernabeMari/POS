using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Models;
using POS.Services;
using System.Reflection;

namespace POS.Services
{
    /// <summary>
    /// Helper class to sanitize inputs in Admin dashboard forms
    /// </summary>
    public static class AdminInputSanitizer
    {
        /// <summary>
        /// Sanitizes all string properties in the user object to prevent SQL injection
        /// </summary>
        public static ApplicationUser SanitizeUser(ApplicationUser user)
        {
            if (user == null) return null;
            
            // Sanitize all string properties
            user.UserName = SqlInputSanitizer.SanitizeString(user.UserName);
            user.Email = SqlInputSanitizer.SanitizeEmail(user.Email);
            user.FullName = SqlInputSanitizer.SanitizeString(user.FullName);
            user.PhoneNumber = SqlInputSanitizer.SanitizeString(user.PhoneNumber);
            
            return user;
        }
        
        /// <summary>
        /// Sanitizes all string properties in the position object
        /// </summary>
        public static Position SanitizePosition(Position position)
        {
            if (position == null) return null;
            
            position.Name = SqlInputSanitizer.SanitizeString(position.Name);
            position.Description = SqlInputSanitizer.SanitizeString(position.Description);
            
            return position;
        }
        
        /// <summary>
        /// Sanitizes all string properties in the product object
        /// </summary>
        public static Product SanitizeProduct(Product product)
        {
            if (product == null) return null;
            
            product.Name = SqlInputSanitizer.SanitizeString(product.Name);
            product.Description = SqlInputSanitizer.SanitizeString(product.Description);
            product.ImageUrl = SqlInputSanitizer.SanitizeString(product.ImageUrl);
            product.ImageDescription = SqlInputSanitizer.SanitizeString(product.ImageDescription);
            
            return product;
        }
        
        /// <summary>
        /// Generic method to sanitize string parameters
        /// </summary>
        public static string SanitizeInput(string input)
        {
            return SqlInputSanitizer.SanitizeString(input);
        }
        
        /// <summary>
        /// Special method for sanitizing IDs while preserving GUID format
        /// </summary>
        /// <param name="id">The ID to sanitize</param>
        /// <returns>Sanitized ID that preserves GUID format</returns>
        public static string SanitizeId(string id)
        {
            if (string.IsNullOrEmpty(id))
                return id;
                
            // Check if this looks like a GUID
            if (id.Length >= 32 && id.Contains("-"))
            {
                // For GUIDs, we only need to check for SQL injection patterns
                // but preserve the GUID format including hyphens
                if (id.Contains("'") || id.Contains("\"") || 
                    id.Contains(";") || id.Contains("--") || 
                    id.Contains("/*") || id.Contains("*/"))
                {
                    // It contains suspicious SQL patterns, use full sanitization
                    return SqlInputSanitizer.SanitizeString(id);
                }
                
                // It looks like a clean GUID, leave it as is
                return id;
            }
            
            // For non-GUID IDs, use regular sanitization
            return SqlInputSanitizer.SanitizeString(id);
        }
    }
    
    /// <summary>
    /// Page filter to sanitize inputs automatically on admin pages
    /// </summary>
    public class AdminSanitizationPageFilter : IPageFilter
    {
        public void OnPageHandlerSelected(PageHandlerSelectedContext context)
        {
            // Nothing to do here
        }

        public void OnPageHandlerExecuting(PageHandlerExecutingContext context)
        {
            // Sanitize all string inputs from the request
            if (context.HandlerArguments != null)
            {
                foreach (var arg in context.HandlerArguments)
                {
                    if (arg.Value is string stringValue)
                    {
                        // Special handling for common ID parameters
                        if (arg.Key.Equals("id", StringComparison.OrdinalIgnoreCase) ||
                            arg.Key.EndsWith("Id", StringComparison.OrdinalIgnoreCase))
                        {
                            context.HandlerArguments[arg.Key] = AdminInputSanitizer.SanitizeId(stringValue);
                        }
                        else
                        {
                            context.HandlerArguments[arg.Key] = SqlInputSanitizer.SanitizeString(stringValue);
                        }
                    }
                }
            }
        }

        public void OnPageHandlerExecuted(PageHandlerExecutedContext context)
        {
            // Nothing to do here
        }
    }
} 