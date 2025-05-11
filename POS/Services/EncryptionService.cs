using System;
using System.Text;

namespace POS.Services
{
    public interface IEncryptionService
    {
        string Encrypt(string plainText);
        string Decrypt(string cipherText);
    }

    public class EncryptionService : IEncryptionService
    {
        // Simple hardcoded encryption key
        private readonly string _encryptionKey = "POS#SystemEncryptionKey2023!";

        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            try
            {
                // Convert input string and key to byte arrays
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] keyBytes = Encoding.UTF8.GetBytes(_encryptionKey);

                // Create output byte array
                byte[] outputBytes = new byte[plainBytes.Length];

                // Simple XOR operation for each byte with cycling through the key
                for (int i = 0; i < plainBytes.Length; i++)
                {
                    outputBytes[i] = (byte)(plainBytes[i] ^ keyBytes[i % keyBytes.Length]);
                }

                // Convert to Base64 for string representation
                return Convert.ToBase64String(outputBytes);
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
                // Convert Base64 string to byte array
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                byte[] keyBytes = Encoding.UTF8.GetBytes(_encryptionKey);
                
                // Create output byte array
                byte[] outputBytes = new byte[cipherBytes.Length];
                
                // XOR operation is symmetric, so we use the same operation for decryption
                for (int i = 0; i < cipherBytes.Length; i++)
                {
                    outputBytes[i] = (byte)(cipherBytes[i] ^ keyBytes[i % keyBytes.Length]);
                }
                
                // Convert back to string
                return Encoding.UTF8.GetString(outputBytes);
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