using System.Collections.Generic;

namespace POS.Models
{
    public class PageTemplate
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string BackgroundColor { get; set; } = "#FFFFFF";
        public string HeaderColor { get; set; } = "#333333";
        public string FooterColor { get; set; } = "#333333";
        public bool IsActive { get; set; } = false;
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime? LastModified { get; set; }

        // Navigation property to elements on this template
        public List<PageElement> Elements { get; set; } = new List<PageElement>();
    }
} 