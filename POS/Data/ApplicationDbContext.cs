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
        public DbSet<LoginSettings> LoginSettings { get; set; }
        public DbSet<Position> Positions { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<Order> Orders { get; set; }

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
        }
    }
} 