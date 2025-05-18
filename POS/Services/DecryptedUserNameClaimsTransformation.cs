using Microsoft.AspNetCore.Authentication;
using POS.Data;
using POS.Models;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;

namespace POS.Services
{
    public class DecryptedUserNameClaimsTransformation : IClaimsTransformation
    {
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<DecryptedUserNameClaimsTransformation> _logger;

        public DecryptedUserNameClaimsTransformation(
            ApplicationDbContext context,
            IEncryptionService encryptionService,
            ILogger<DecryptedUserNameClaimsTransformation> logger)
        {
            _context = context;
            _encryptionService = encryptionService;
            _logger = logger;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            // Check if we're dealing with an authenticated user
            if (principal?.Identity == null || !principal.Identity.IsAuthenticated)
            {
                return principal;
            }

            // Get the user ID from claims
            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return principal;
            }

            try
            {
                // Find the user in the database
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == userId);
                if (user == null)
                {
                    return principal;
                }

                // Get the current name claim
                var nameClaim = principal.FindFirst(ClaimTypes.Name);
                if (nameClaim == null)
                {
                    return principal;
                }

                // Try to decrypt the username
                string decryptedUserName = nameClaim.Value;

                try
                {
                    // Check if the username is encrypted
                    if (IsValidBase64(user.UserName))
                    {
                        decryptedUserName = _encryptionService.Decrypt(user.UserName);
                    }
                    // If not encrypted, use as is
                    else
                    {
                        decryptedUserName = user.UserName;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to decrypt username for claims transformation");
                    // Keep the existing claim value if decryption fails
                }

                // Create a new claims identity with the decrypted username
                var identity = new ClaimsIdentity(principal.Identity);
                identity.RemoveClaim(nameClaim);
                identity.AddClaim(new Claim(ClaimTypes.Name, decryptedUserName));

                // Create a new principal with the updated identity
                var newPrincipal = new ClaimsPrincipal(identity);
                foreach (var id in principal.Identities.Where(i => i != principal.Identity))
                {
                    newPrincipal.AddIdentity(id);
                }

                return newPrincipal;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error transforming claims");
                return principal;
            }
        }

        // Helper method to check if a string might be encrypted
        private bool IsValidBase64(string input)
        {
            // We're no longer using Base64, but we still need to detect if a string is likely encrypted
            // Just check if it contains only letters (since our encryption only modifies letters)
            
            if (string.IsNullOrEmpty(input))
                return false;
                
            // If it contains only alphabetic characters, it could be encrypted
            bool hasOnlyLetters = input.All(c => char.IsLetter(c));
            if (hasOnlyLetters && input.Length > 3)
            {
                // Assume it's probably encrypted
                return true;
            }
            
            return false;
        }
    }
} 