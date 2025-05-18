using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;

namespace POS.Areas.User.Pages
{
    [Authorize(Roles = "User")]
    public class IndexModel : PageModel
    {
        public void OnGet()
        {
        }
    }
} 