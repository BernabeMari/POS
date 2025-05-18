using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using POS.Models;

namespace POS.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<PageElement> PageElements { get; set; }
        public DbSet<PageTemplate> PageTemplates { get; set; }
        public DbSet<PageElementImage> PageElementImages { get; set; }
        public DbSet<ProductIngredient> ProductIngredients { get; set; }
        public DbSet<LoginSettings> LoginSettings { get; set; }
        public DbSet<Position> Positions { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<Category> Categories { get; set; }
        public DbSet<InventoryLog> InventoryLogs { get; set; }
        public DbSet<Stock> Stocks { get; set; }
        public DbSet<StockHistory> StockHistory { get; set; }
        public DbSet<WalletTransaction> WalletTransactions { get; set; }
        public DbSet<Wallet> Wallets { get; set; }
        public DbSet<CartItem> CartItems { get; set; }
        public DbSet<UserPreference> UserPreferences { get; set; }
        public DbSet<EncryptionSettings> EncryptionSettings { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            
            // Configure relationships and any additional constraints
            builder.Entity<PageTemplate>()
                .HasMany(t => t.Elements)
                .WithOne()
                .HasForeignKey("PageTemplateId")
                .OnDelete(DeleteBehavior.Cascade);
                
            // Configure relationship between PageElement and PageElementImage
            builder.Entity<PageElementImage>()
                .HasOne(i => i.PageElement)
                .WithMany(e => e.Images)
                .HasForeignKey(i => i.PageElementId)
                .OnDelete(DeleteBehavior.Cascade);
                
            // Configure relationship between PageElement and ProductIngredient
            builder.Entity<ProductIngredient>()
                .HasOne(i => i.PageElement)
                .WithMany(e => e.Ingredients)
                .HasForeignKey(i => i.PageElementId)
                .OnDelete(DeleteBehavior.Cascade);
                
            // Configure precision for ProductIngredient
            builder.Entity<ProductIngredient>()
                .Property(pi => pi.Quantity)
                .HasPrecision(18, 2);
                
            // Configure relationship between ApplicationUser and Position
            builder.Entity<ApplicationUser>()
                .HasOne(u => u.Position)
                .WithMany()
                .HasForeignKey(u => u.PositionId)
                .IsRequired(false)
                .OnDelete(DeleteBehavior.SetNull);
                
            // Configure Position entity to map to AspUserPositions table
            builder.Entity<Position>().ToTable("AspUserPositions");
            
            // Configure Order relationships
            builder.Entity<Order>()
                .HasOne(o => o.User)
                .WithMany()
                .HasForeignKey(o => o.UserId)
                .OnDelete(DeleteBehavior.Restrict);
                
            builder.Entity<Order>()
                .HasOne(o => o.AssignedEmployee)
                .WithMany()
                .HasForeignKey(o => o.AssignedToEmployeeId)
                .IsRequired(false)
                .OnDelete(DeleteBehavior.SetNull);
                
            // Configure CartItem relationships and schema
            builder.Entity<CartItem>(entity => 
            {
                // Primary key
                entity.HasKey(e => e.Id);
                
                // Configure relationship with User
                entity.HasOne(c => c.User)
                    .WithMany()
                    .HasForeignKey(c => c.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
                
                // Configure properties
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.ProductName).IsRequired();
                entity.Property(e => e.ProductImageUrl).IsRequired();
                entity.Property(e => e.ProductImageDescription).HasMaxLength(500);
                entity.Property(e => e.Price).HasPrecision(18, 2).IsRequired();
                entity.Property(e => e.Quantity).IsRequired();
                entity.Property(e => e.CreatedAt).IsRequired();
                
                // Configure table name explicitly
                entity.ToTable("CartItems");
            });
                
            // Configure precision for decimal properties
            builder.Entity<Order>()
                .Property(o => o.Price)
                .HasPrecision(18, 2);
                
            builder.Entity<Order>()
                .Property(o => o.TotalPrice)
                .HasPrecision(18, 2);
                
            builder.Entity<Product>()
                .Property(p => p.Price)
                .HasPrecision(18, 2);
                
            builder.Entity<PageElement>()
                .Property(pe => pe.ProductPrice)
                .HasPrecision(18, 2);
                
            // Configure precision for Stock and StockHistory decimal properties
            builder.Entity<Stock>()
                .Property(s => s.Quantity)
                .HasPrecision(10, 2);
                
            builder.Entity<Stock>()
                .Property(s => s.ThresholdLevel)
                .HasPrecision(10, 2);
                
            builder.Entity<StockHistory>()
                .Property(sh => sh.PreviousQuantity)
                .HasPrecision(10, 2);
                
            builder.Entity<StockHistory>()
                .Property(sh => sh.NewQuantity)
                .HasPrecision(10, 2);
                
            // Configure Wallet and WalletTransaction relationships
            builder.Entity<Wallet>()
                .HasOne(w => w.User)
                .WithMany()
                .HasForeignKey(w => w.UserId)
                .OnDelete(DeleteBehavior.Cascade);
                
            builder.Entity<WalletTransaction>()
                .HasOne(wt => wt.User)
                .WithMany()
                .HasForeignKey(wt => wt.UserId)
                .OnDelete(DeleteBehavior.Restrict);
                
            builder.Entity<WalletTransaction>()
                .Property(wt => wt.Amount)
                .HasPrecision(18, 2);
                
            builder.Entity<WalletTransaction>()
                .Property(wt => wt.PreviousBalance)
                .HasPrecision(18, 2);
                
            builder.Entity<WalletTransaction>()
                .Property(wt => wt.NewBalance)
                .HasPrecision(18, 2);
                
            // Set default precision for ApplicationUser.WalletBalance to avoid warnings
            builder.Entity<ApplicationUser>()
                .Property(u => u.WalletBalance)
                .HasPrecision(18, 2);
                
            // Configure UserPreference entity
            builder.Entity<UserPreference>()
                .HasIndex(p => new { p.UserId, p.Key })
                .IsUnique();
                
            builder.Entity<UserPreference>()
                .HasOne(p => p.User)
                .WithMany()
                .HasForeignKey(p => p.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
} 