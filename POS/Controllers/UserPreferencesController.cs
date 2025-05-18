using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using POS.Data;
using POS.Models;
using System.Threading.Tasks;
using System;
using Microsoft.Extensions.Logging;

namespace POS.Controllers
{
    [Route("api/user-preferences")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class UserPreferencesController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<UserPreferencesController> _logger;

        public UserPreferencesController(
            ApplicationDbContext context, 
            ILogger<UserPreferencesController> logger)
        {
            _context = context;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Get([FromQuery] string userId, [FromQuery] string key)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(key))
            {
                return BadRequest(new { success = false, message = "UserId and key are required" });
            }

            var preference = await _context.UserPreferences
                .FirstOrDefaultAsync(p => p.UserId == userId && p.Key == key);

            return Ok(preference ?? new UserPreference
            {
                UserId = userId,
                Key = key,
                Value = "false"
            });
        }

        // Simple DTO class for deserializing the preference data
        public class UserPreferenceDto
        {
            public string UserId { get; set; }
            public string Key { get; set; }
            public string Value { get; set; }
        }

        [HttpPost]
        public async Task<IActionResult> Post([FromBody] UserPreferenceDto model)
        {
            try
            {
                if (model == null)
                {
                    return BadRequest(new { success = false, message = "No data provided" });
                }

                _logger.LogInformation($"Received preference: UserId={model.UserId}, Key={model.Key}, Value={model.Value}");

                if (string.IsNullOrEmpty(model.UserId) || string.IsNullOrEmpty(model.Key))
                {
                    return BadRequest(new { success = false, message = "UserId and key are required" });
                }

                var existing = await _context.UserPreferences
                    .FirstOrDefaultAsync(p => p.UserId == model.UserId && p.Key == model.Key);

                if (existing != null)
                {
                    // Update existing preference
                    existing.Value = model.Value;
                    _logger.LogInformation($"Updated existing preference for user {model.UserId}");
                }
                else
                {
                    // Create new preference
                    _context.UserPreferences.Add(new UserPreference
                    {
                        UserId = model.UserId,
                        Key = model.Key,
                        Value = model.Value
                    });
                    _logger.LogInformation($"Created new preference for user {model.UserId}");
                }

                await _context.SaveChangesAsync();
                return Ok(new { success = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving preference");
                return StatusCode(500, new { success = false, message = ex.Message });
            }
        }
    }
}