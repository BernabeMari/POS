using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using POS.Models;
using System.Security.Claims;

namespace POS.Services
{
    public class DecryptedUserNameClaimsTransformation : IClaimsTransformation
    {
        private readonly IEncryptionService _encryptionService;
        private readonly ILogger<DecryptedUserNameClaimsTransformation> _logger;

        public DecryptedUserNameClaimsTransformation(
            IEncryptionService encryptionService,
            ILogger<DecryptedUserNameClaimsTransformation> logger)
        {
            _encryptionService = encryptionService;
            _logger = logger;
        }

        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            if (principal == null || principal.Identity == null || !principal.Identity.IsAuthenticated)
            {
                return Task.FromResult(principal);
            }

            var claimsIdentity = principal.Identity as ClaimsIdentity;
            if (claimsIdentity == null)
            {
                return Task.FromResult(principal);
            }

            try
            {
                _logger.LogDebug("Processing claims transformation for user");
                
                // List of claim types that could contain encrypted usernames
                var claimTypesToCheck = new[]
                {
                    ClaimTypes.Name,
                    ClaimTypes.NameIdentifier,
                    "preferred_username",
                    "username"
                };

                foreach (var claimType in claimTypesToCheck)
                {
                    var claim = claimsIdentity.FindFirst(claimType);
                    if (claim != null)
                    {
                        _logger.LogDebug($"Processing claim {claimType} with value: {claim.Value}");
                        
                        // Check if the claim value needs decryption
                        if (IsValidBase64(claim.Value))
                        {
                            try
                            {
                                // Try to decrypt the value
                                string decryptedValue = _encryptionService.Decrypt(claim.Value);
                                _logger.LogInformation($"Decrypted claim {claimType}: {decryptedValue}");
                                
                                // Remove the encrypted claim
                                claimsIdentity.RemoveClaim(claim);
                                
                                // Add the decrypted claim
                                claimsIdentity.AddClaim(new Claim(claimType, decryptedValue));
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, $"Failed to decrypt claim {claimType}: {claim.Value}");
                                // If decryption fails, keep the original value
                            }
                        }
                        else 
                        {
                            _logger.LogDebug($"Claim {claimType} does not appear to be encrypted: {claim.Value}");
                        }
                    }
                    else
                    {
                        _logger.LogDebug($"Claim {claimType} not found");
                    }
                }
                
                // Special handling for Identity.Name if it's missing or still encrypted
                var nameProperty = principal.Identity.Name;
                if (nameProperty != null && IsValidBase64(nameProperty))
                {
                    try
                    {
                        // Try to decrypt directly
                        string decryptedName = _encryptionService.Decrypt(nameProperty);
                        _logger.LogInformation($"Identity.Name decrypted from: {nameProperty} to: {decryptedName}");
                        
                        // For ClaimsIdentity, setting Name requires adding a claim
                        if (claimsIdentity.FindFirst(ClaimTypes.Name) == null)
                        {
                            claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, decryptedName));
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, $"Failed to decrypt Identity.Name: {nameProperty}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in DecryptedUserNameClaimsTransformation");
            }

            return Task.FromResult(principal);
        }

        // Helper method to check if a string is valid Base64
        private bool IsValidBase64(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;
                
            try
            {
                Convert.FromBase64String(input);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
} 