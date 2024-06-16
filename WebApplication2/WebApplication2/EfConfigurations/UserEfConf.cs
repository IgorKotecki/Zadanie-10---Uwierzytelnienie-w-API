using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using WebApplication1.Models;

namespace WebApplication1.EfConfigurations;

public class UserEfConf :IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("AppUser");

        builder.HasKey(u => u.IdUser);
        builder.Property(u => u.IdUser).ValueGeneratedOnAdd();

        builder.Property(u => u.Login).IsRequired().HasMaxLength(100);
        builder.Property(u => u.Password).IsRequired().HasMaxLength(200);
        builder.Property(u => u.Salt).IsRequired().HasMaxLength(100);
        builder.Property(u => u.RefreshToken).HasMaxLength(200);
        builder.Property(u => u.RefreshTokenExp);
    }
}