using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;

namespace POS.Areas.Admin.Pages
{
    [Authorize(Policy = "RequireAdministratorRole")]
    public class IndexModel : PageModel
    {
        public void OnGet()
        {
        }
    }
} 