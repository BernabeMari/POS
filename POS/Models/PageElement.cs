namespace POS.Models
{
    public class PageElement
    {
        public int Id { get; set; }
        public string PageName { get; set; } = string.Empty; // e.g., "Login", "Signup", "Dashboard"
        public string ElementType { get; set; } = string.Empty; // e.g., "InputField", "Button", "Label"
        public string ElementId { get; set; } = string.Empty; // Unique identifier for the element
        public string Text { get; set; } = string.Empty; // The text to display
        public string Color { get; set; } = "#000000"; // The color of the element
        public int PositionX { get; set; } // X coordinate for position
        public int PositionY { get; set; } // Y coordinate for position
        public int Width { get; set; } = 200; // Default width
        public int Height { get; set; } = 40; // Default height
        public string AdditionalStyles { get; set; } = string.Empty; // Any additional CSS
        public bool IsVisible { get; set; } = true;
        public DateTime LastModified { get; set; } = DateTime.Now;
        public string ImageUrl { get; set; } = string.Empty; // URL for image elements
        public string ImageDescription { get; set; } = string.Empty; // Description for image elements
        
        // Product-related fields for product images
        public string ProductName { get; set; } = string.Empty;
        public decimal ProductPrice { get; set; }
        public string ProductDescription { get; set; } = string.Empty;
        public bool IsProduct { get; set; } = false; // Flag to identify if this element represents a product
        public int ProductStockQuantity { get; set; }
        public bool IsAvailable { get; set; } = true; // Flag to indicate if the product is available for ordering
        
        public List<PageElementImage> Images { get; set; } = new List<PageElementImage>(); // Collection of images for an element
        
        // Product ingredients
        public List<ProductIngredient> Ingredients { get; set; } = new List<ProductIngredient>(); // Collection of ingredients for a product
    }

    public class PageElementImage
    {
        public int Id { get; set; }
        public int PageElementId { get; set; }
        public PageElement PageElement { get; set; }
        public string Base64Data { get; set; } = string.Empty; // Base64 encoded image data
        public string Description { get; set; } = string.Empty; // Description for this specific image
    }
} 