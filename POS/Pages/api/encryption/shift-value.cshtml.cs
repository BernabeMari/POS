using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using POS.Services;

namespace POS.Pages.Api.Encryption
{
    public class ShiftValueModel : PageModel
    {
        private readonly IEncryptionService _encryptionService;

        public ShiftValueModel(IEncryptionService encryptionService)
        {
            _encryptionService = encryptionService;
        }

        public int ShiftValue { get; set; }

        public void OnGet()
        {
            ShiftValue = _encryptionService.GetShiftValue();
        }
    }
} 