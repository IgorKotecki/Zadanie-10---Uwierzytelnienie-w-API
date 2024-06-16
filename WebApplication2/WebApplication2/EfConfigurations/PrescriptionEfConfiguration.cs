using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using WebApplication1.Models;

namespace WebApplication1.EfConfigurations;

public class PrescriptionEfConfiguration : IEntityTypeConfiguration<Prescription>
{
    public void Configure(EntityTypeBuilder<Prescription> builder)
    {
        builder.ToTable("Prescription");

        builder.HasKey(p => p.IdPrescription);
        builder.Property(p => p.IdPrescription).ValueGeneratedOnAdd();

        builder.Property(p => p.Date).IsRequired();
        builder.Property(p => p.DueDate).IsRequired();
        
        builder.HasOne(p => p.Doctor)
            .WithMany(d => d.Prescriptions)
            .HasForeignKey(p => p.IdDoctor);

        builder.HasOne(p => p.Patient)
            .WithMany(pa => pa.Prescriptions)
            .HasForeignKey(p => p.IdPatient);
    }
}