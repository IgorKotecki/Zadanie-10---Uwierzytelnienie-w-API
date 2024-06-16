using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using WebApplication1.Models;

namespace WebApplication1.EfConfigurations;

public class Prescription_MedicamentEfConfiguration : IEntityTypeConfiguration<Prescription_Medicament>
{
    public void Configure(EntityTypeBuilder<Prescription_Medicament> builder)
    {
        builder.ToTable("Prescription_Medicament");

        builder.HasKey(g => g.IdMedicament);
        builder.HasKey(g => g.IdPrescription);

        builder.Property(g => g.Dose).IsRequired();
        builder.Property(g => g.Details).IsRequired().HasMaxLength(100);
        
        builder.HasOne(pm => pm.Prescription)
            .WithMany(p => p.PrescriptionMedicaments)
            .HasForeignKey(pm => pm.IdPrescription);

        builder.HasOne(pm => pm.Medicament)
            .WithMany(m => m.PrescriptionMedicaments)
            .HasForeignKey(pm => pm.IdMedicament);
    }
}