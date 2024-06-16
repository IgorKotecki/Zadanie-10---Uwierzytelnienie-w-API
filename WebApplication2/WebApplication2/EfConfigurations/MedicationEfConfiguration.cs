using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using WebApplication1.Models;

namespace WebApplication1.EfConfigurations;

public class MedicationEfConfiguration : IEntityTypeConfiguration<Medicament>
{
    public void Configure(EntityTypeBuilder<Medicament> builder)
    {
        builder.ToTable("Medicament");

        builder.HasKey(m => m.IdMedicament);
        builder.Property(m => m.IdMedicament).ValueGeneratedOnAdd();

        builder.Property(m => m.Name).IsRequired().HasMaxLength(100);
        builder.Property(m => m.Description).IsRequired().HasMaxLength(100);
        builder.Property(m => m.Type).IsRequired().HasMaxLength(100);
        
    }
}