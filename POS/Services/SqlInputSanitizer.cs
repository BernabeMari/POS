using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace POS.Services
{
    /// <summary>
    /// Utility class for sanitizing input to prevent SQL injection attacks
    /// Use this class when dealing with any input that might be used in SQL queries,
    /// especially if you are ever forced to use raw SQL queries outside of Entity Framework.
    /// </summary>
    public static class SqlInputSanitizer
    {
        /// <summary>
        /// Sanitizes string input to prevent SQL injection by removing potentially dangerous characters
        /// </summary>
        /// <param name="input">The input string to sanitize</param>
        /// <returns>A sanitized string safe to use in SQL queries</returns>
        public static string SanitizeString(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // Remove any characters that could be used for SQL injection
            // This includes: SQL comment markers, semicolons, quotes, etc.
            string sanitized = Regex.Replace(input, @"[;'""\*%_\\]", "");
            sanitized = sanitized.Replace("--", "");
            sanitized = sanitized.Replace("/*", "");
            sanitized = sanitized.Replace("*/", "");
            sanitized = sanitized.Replace("@@", "");

            // Remove SQL keywords and operators (case-insensitive)
            string[] sqlKeywords = new[] {
                "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
                "CREATE", "EXECUTE", "EXEC", "UNION", "HAVING", "ORDER BY",
                "GROUP BY", "OR", "AND", "FROM", "WHERE", "JOIN", "TRUNCATE",
                "DECLARE", "CAST", "CONVERT", "NCHAR", "WAITFOR", "DELAY"
            };

            // Additional multi-word SQL keywords that need special handling
            string[] multiWordKeywords = new[] {
                "DROP TABLE", "CREATE TABLE", "ALTER TABLE", "DELETE FROM",
                "INSERT INTO", "UPDATE SET", "SELECT FROM", "EXECUTE IMMEDIATE"
            };

            // Remove single word SQL keywords
            foreach (var keyword in sqlKeywords)
            {
                sanitized = Regex.Replace(sanitized, $@"\b{keyword}\b", "", RegexOptions.IgnoreCase);
            }

            // Remove multi-word SQL keywords
            foreach (var keyword in multiWordKeywords)
            {
                sanitized = Regex.Replace(sanitized, keyword, "", RegexOptions.IgnoreCase);
            }

            return sanitized;
        }

        /// <summary>
        /// Sanitizes an email address while preserving the @ symbol for valid email formats
        /// </summary>
        /// <param name="email">The email address to sanitize</param>
        /// <returns>A sanitized email address safe to use in SQL queries while preserving valid email format</returns>
        public static string SanitizeEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return email;

            // Remove any characters that could be used for SQL injection
            // This includes: SQL comment markers, semicolons, quotes, etc.
            string sanitized = Regex.Replace(email, @"[;'""\*%_\\]", "");
            sanitized = sanitized.Replace("--", "");
            sanitized = sanitized.Replace("/*", "");
            sanitized = sanitized.Replace("*/", "");
            sanitized = sanitized.Replace("@@", ""); // Double @ is still dangerous
            // But keep single @ for emails

            // Remove SQL keywords and operators (case-insensitive)
            string[] sqlKeywords = new[] {
                "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
                "CREATE", "EXECUTE", "EXEC", "UNION", "HAVING", "ORDER BY",
                "GROUP BY", "OR", "AND", "FROM", "WHERE", "JOIN", "TRUNCATE",
                "DECLARE", "CAST", "CONVERT", "NCHAR", "WAITFOR", "DELAY"
            };

            // Additional multi-word SQL keywords that need special handling
            string[] multiWordKeywords = new[] {
                "DROP TABLE", "CREATE TABLE", "ALTER TABLE", "DELETE FROM",
                "INSERT INTO", "UPDATE SET", "SELECT FROM", "EXECUTE IMMEDIATE"
            };

            // Remove single word SQL keywords
            foreach (var keyword in sqlKeywords)
            {
                sanitized = Regex.Replace(sanitized, $@"\b{keyword}\b", "", RegexOptions.IgnoreCase);
            }

            // Remove multi-word SQL keywords
            foreach (var keyword in multiWordKeywords)
            {
                sanitized = Regex.Replace(sanitized, keyword, "", RegexOptions.IgnoreCase);
            }

            return sanitized;
        }

        /// <summary>
        /// Validates if a string only contains alphanumeric characters and basic punctuation
        /// </summary>
        /// <param name="input">String to validate</param>
        /// <returns>True if string only contains safe characters</returns>
        public static bool IsSafeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return true;

            // Only allow alphanumeric, spaces, and some punctuation
            return Regex.IsMatch(input, @"^[a-zA-Z0-9\s.,!?()-_+]*$");
        }

        /// <summary>
        /// Sanitizes a string that should only contain alphanumeric characters
        /// </summary>
        /// <param name="input">String to sanitize</param>
        /// <returns>Sanitized alphanumeric string</returns>
        public static string SanitizeAlphanumeric(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // Strip anything that's not alphanumeric
            return Regex.Replace(input, @"[^a-zA-Z0-9]", "");
        }

        /// <summary>
        /// Validates if a number string contains only numeric characters
        /// </summary>
        /// <param name="input">String to validate as a number</param>
        /// <returns>True if string only contains numeric characters</returns>
        public static bool IsNumeric(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            // Allow only digits and decimal point
            return Regex.IsMatch(input, @"^[0-9]+(\.[0-9]+)?$");
        }

        /// <summary>
        /// Sanitizes a parameter name for use in SQL queries
        /// </summary>
        /// <param name="paramName">Parameter name to sanitize</param>
        /// <returns>Sanitized parameter name</returns>
        public static string SanitizeParameterName(string paramName)
        {
            if (string.IsNullOrEmpty(paramName))
                return paramName;

            // Only allow alphanumeric and underscore for parameter names
            return Regex.Replace(paramName, @"[^a-zA-Z0-9_]", "");
        }
    }
} 