using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System;

namespace POS.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ImageController : ControllerBase
    {
        [HttpPost("upload")]
        public async Task<IActionResult> UploadImages(List<IFormFile> files)
        {
            try
            {
                var results = new List<ImageUploadResult>();

                foreach (var file in files)
                {
                    if (file.Length > 0)
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
                }

                return Ok(results);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        public class ImageUploadResult
        {
            public string Base64Data { get; set; }
            public string FileName { get; set; }
            public string ContentType { get; set; }
            public long Size { get; set; }
        }
    }
} 