using Microsoft.EntityFrameworkCore;
using WebApplication1.Models;

public class AppDbContext : DbContext
{
    public DbSet<UserModel> Users { get; set; }
    public DbSet<UserProfile> UserProfiles { get; set; }

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserModel>()
            .HasOne(u => u.Profile)
            .WithOne(p => p.User)
            .HasForeignKey<UserProfile>(p => p.UserID);
    }
}
