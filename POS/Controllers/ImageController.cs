using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System;
using Microsoft.AspNetCore.Http.Features;

namespace POS.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ImageController : ControllerBase
    {
        [HttpPost("upload")]
        [RequestFormLimits(MultipartBodyLengthLimit = 50 * 1024 * 1024)] // 50MB
        [RequestSizeLimit(50 * 1024 * 1024)] // 50MB
        public async Task<IActionResult> UploadImages(List<IFormFile> files)
        {
            try
            {
                var results = new List<ImageUploadResult>();

                foreach (var file in files)
                {
                    if (file.Length > 0)
                    {
                        if (file.Length > 10 * 1024 * 1024) // 10MB limit per file
                        {
                            return BadRequest($"File {file.FileName} exceeds the 10MB limit. Please compress or resize the image.");
                        }

                        try
                        {
                            // Convert to Base64
                            using var memoryStream = new MemoryStream();
                            await file.CopyToAsync(memoryStream);
                            var bytes = memoryStream.ToArray();
                            var base64String = $"data:{file.ContentType};base64,{Convert.ToBase64String(bytes)}";

                            results.Add(new ImageUploadResult
                            {
                                Base64Data = base64String,
                                FileName = file.FileName,
                                ContentType = file.ContentType,
                                Size = file.Length
                            });
                        }
                        catch (Exception ex)
                        {
                            return StatusCode(500, $"Error processing file {file.FileName}: {ex.Message}");
                        }
                    }
                }

                return Ok(results);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // Endpoint to validate an image URL or base64 string
        [HttpPost("validate")]
        public IActionResult ValidateImage([FromBody] ValidateImageRequest request)
        {
            try
            {
                if (string.IsNullOrEmpty(request.ImageData))
                {
                    return BadRequest("No image data provided");
                }

                // Check if it's a base64 image
                if (request.ImageData.StartsWith("data:image"))
                {
                    // Extract the base64 part (after the comma)
                    int commaIndex = request.ImageData.IndexOf(',');
                    if (commaIndex < 0)
                    {
                        return BadRequest("Invalid base64 image format");
                    }

                    string base64Data = request.ImageData.Substring(commaIndex + 1);
                    
                    try
                    {
                        // Try to decode it to verify it's valid
                        byte[] imageBytes = Convert.FromBase64String(base64Data);
                        return Ok(new { isValid = true, message = "Valid base64 image" });
                    }
                    catch
                    {
                        return BadRequest("Invalid base64 encoding");
                    }
                }
                
                // It's a URL - could add URL validation here if needed
                return Ok(new { isValid = true, message = "Valid image URL" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error validating image: {ex.Message}");
            }
        }

        public class ImageUploadResult
        {
            public string Base64Data { get; set; }
            public string FileName { get; set; }
            public string ContentType { get; set; }
            public long Size { get; set; }
        }
        
        public class ValidateImageRequest
        {
            public string ImageData { get; set; }
        }
    }
} 