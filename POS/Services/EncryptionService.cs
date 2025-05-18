using System;
using System.Text;
using System.Linq;
using POS.Data;

namespace POS.Services
{
    public interface IEncryptionService
    {
        string Encrypt(string plainText);
        string Decrypt(string cipherText);
        int GetShiftValue();
        bool UpdateShiftValue(int newShiftValue, string modifiedBy);
    }

    public class EncryptionService : IEncryptionService
    {
        private readonly ApplicationDbContext _context;
        private int? _cachedShiftValue;
        private const string SHIFT_VALUE_SETTING = "CaesarShiftValue";
        private const int DEFAULT_SHIFT_VALUE = 7;

        public EncryptionService(ApplicationDbContext context)
        {
            _context = context;
        }

        private int GetCaesarShiftValue()
        {
            // Return cached value if available
            if (_cachedShiftValue.HasValue)
                return _cachedShiftValue.Value;
            
            // Get from database
            var setting = _context.EncryptionSettings
                .FirstOrDefault(s => s.SettingName == SHIFT_VALUE_SETTING);
            
            // If not found, use default and try to create it
            if (setting == null)
            {
                try
                {
                    setting = new Models.EncryptionSettings
                    {
                        SettingName = SHIFT_VALUE_SETTING,
                        SettingValue = DEFAULT_SHIFT_VALUE.ToString(),
                        Description = "Shift value used for Caesar cipher encryption",
                        ModifiedBy = "System"
                    };
                    
                    _context.EncryptionSettings.Add(setting);
                    _context.SaveChanges();
                    
                    _cachedShiftValue = DEFAULT_SHIFT_VALUE;
                    return DEFAULT_SHIFT_VALUE;
                }
                catch (Exception ex)
                {
                    // Log the exception
                    Console.WriteLine($"Error creating encryption settings: {ex.Message}");
                    return DEFAULT_SHIFT_VALUE;
                }
            }
            
            // Parse the setting value
            if (int.TryParse(setting.SettingValue, out int shiftValue))
            {
                _cachedShiftValue = shiftValue;
                return shiftValue;
            }
            
            // If parsing fails, return default
            return DEFAULT_SHIFT_VALUE;
        }

        public int GetShiftValue()
        {
            return GetCaesarShiftValue();
        }

        public bool UpdateShiftValue(int newShiftValue, string modifiedBy)
        {
            try
            {
                // Ensure shift value is between 1 and 25
                if (newShiftValue < 1 || newShiftValue > 25)
                    return false;
                
                // Keep track of the old shift value
                int oldShiftValue = GetCaesarShiftValue();
                
                // Update the shift value in the database
                var setting = _context.EncryptionSettings
                    .FirstOrDefault(s => s.SettingName == SHIFT_VALUE_SETTING);
                
                if (setting == null)
                {
                    setting = new Models.EncryptionSettings
                    {
                        SettingName = SHIFT_VALUE_SETTING,
                        SettingValue = newShiftValue.ToString(),
                        Description = "Shift value used for Caesar cipher encryption",
                        ModifiedBy = modifiedBy,
                        LastModified = DateTime.UtcNow
                    };
                    
                    _context.EncryptionSettings.Add(setting);
                }
                else
                {
                    setting.SettingValue = newShiftValue.ToString();
                    setting.ModifiedBy = modifiedBy;
                    setting.LastModified = DateTime.UtcNow;
                    
                    _context.EncryptionSettings.Update(setting);
                }
                
                _context.SaveChanges();
                
                // Update cache
                _cachedShiftValue = newShiftValue;
                
                // Re-encrypt all user data with the new shift value
                ReEncryptAllUserData(oldShiftValue, newShiftValue);
                
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void ReEncryptAllUserData(int oldShiftValue, int newShiftValue)
        {
            try
            {
                // Get all users
                var users = _context.Users.ToList();
                
                foreach (var user in users)
                {
                    // Keep track of whether changes were made
                    bool isChanged = false;
                    
                    // Re-encrypt username
                    if (!string.IsNullOrEmpty(user.UserName))
                    {
                        // First decrypt with old shift value
                        string decryptedUserName = DecryptWithShiftValue(user.UserName, oldShiftValue);
                        
                        // Then encrypt with new shift value
                        user.UserName = EncryptWithShiftValue(decryptedUserName, newShiftValue);
                        user.NormalizedUserName = user.UserName.ToUpper();
                        isChanged = true;
                    }
                    
                    // Re-encrypt email
                    if (!string.IsNullOrEmpty(user.Email))
                    {
                        // First decrypt with old shift value
                        string decryptedEmail = DecryptWithShiftValue(user.Email, oldShiftValue);
                        
                        // Then encrypt with new shift value
                        user.Email = EncryptWithShiftValue(decryptedEmail, newShiftValue);
                        user.NormalizedEmail = user.Email.ToUpper();
                        isChanged = true;
                    }
                    
                    // Re-encrypt full name
                    if (!string.IsNullOrEmpty(user.FullName))
                    {
                        // First decrypt with old shift value
                        string decryptedFullName = DecryptWithShiftValue(user.FullName, oldShiftValue);
                        
                        // Then encrypt with new shift value
                        user.FullName = EncryptWithShiftValue(decryptedFullName, newShiftValue);
                        isChanged = true;
                    }
                    
                    // Save changes if any were made
                    if (isChanged)
                    {
                        _context.Users.Update(user);
                    }
                }
                
                // Save all changes
                _context.SaveChanges();
            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"Error re-encrypting user data: {ex.Message}");
            }
        }
        
        // Helper methods for encrypting and decrypting with a specific shift value
        private string EncryptWithShiftValue(string plainText, int shiftValue)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            try
            {
                StringBuilder result = new StringBuilder();
                
                foreach (char c in plainText)
                {
                    if (char.IsLetter(c))
                    {
                        char baseChar = char.IsUpper(c) ? 'A' : 'a';
                        char encryptedChar = (char)(((c - baseChar + shiftValue) % 26) + baseChar);
                        result.Append(encryptedChar);
                    }
                    else
                    {
                        result.Append(c);
                    }
                }
                
                return result.ToString();
            }
            catch
            {
                return plainText;
            }
        }
        
        private string DecryptWithShiftValue(string cipherText, int shiftValue)
        {
            if (string.IsNullOrEmpty(cipherText))
                return cipherText;

            try
            {
                StringBuilder result = new StringBuilder();
                
                foreach (char c in cipherText)
                {
                    if (char.IsLetter(c))
                    {
                        char baseChar = char.IsUpper(c) ? 'A' : 'a';
                        char decryptedChar = (char)(((c - baseChar - shiftValue + 26) % 26) + baseChar);
                        result.Append(decryptedChar);
                    }
                    else
                    {
                        result.Append(c);
                    }
                }
                
                return result.ToString();
            }
            catch
            {
                return cipherText;
            }
        }

        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            try
            {
                // Get the shift value from the database
                int shiftValue = GetCaesarShiftValue();
                
                StringBuilder result = new StringBuilder();
                
                // Apply Caesar cipher shift to each character
                foreach (char c in plainText)
                {
                    // Only encrypt letters (both uppercase and lowercase)
                    if (char.IsLetter(c))
                    {
                        char baseChar = char.IsUpper(c) ? 'A' : 'a';
                        // Apply shift with wrap-around within the alphabet (mod 26)
                        char encryptedChar = (char)(((c - baseChar + shiftValue) % 26) + baseChar);
                        result.Append(encryptedChar);
                    }
                    else
                    {
                        // Non-letter characters remain unchanged
                        result.Append(c);
                    }
                }
                
                // Return the Caesar cipher result directly without Base64 encoding
                return result.ToString();
            }
            catch (Exception ex)
            {
                // In production, log the exception
                Console.WriteLine($"Error encrypting data: {ex.Message}");
                return plainText; // Return original text on error
            }
        }

        public string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                return cipherText;

            try
            {
                // Get the shift value from the database
                int shiftValue = GetCaesarShiftValue();
                
                StringBuilder result = new StringBuilder();
                
                // Apply reverse Caesar cipher shift to each character
                foreach (char c in cipherText)
                {
                    // Only decrypt letters (both uppercase and lowercase)
                    if (char.IsLetter(c))
                    {
                        char baseChar = char.IsUpper(c) ? 'A' : 'a';
                        // Apply reverse shift with wrap-around within the alphabet (mod 26)
                        // Add 26 before modulo to handle negative numbers
                        char decryptedChar = (char)(((c - baseChar - shiftValue + 26) % 26) + baseChar);
                        result.Append(decryptedChar);
                    }
                    else
                    {
                        // Non-letter characters remain unchanged
                        result.Append(c);
                    }
                }
                
                return result.ToString();
            }
            catch (Exception ex)
            {
                // In production, log the exception
                Console.WriteLine($"Error decrypting data: {ex.Message}");
                return cipherText; // Return encrypted text on error
            }
        }
    }
} 