using Microsoft.EntityFrameworkCore;
using WebApplication1.EfConfigurations;
using WebApplication1.Models;
using Patient = WebApplication1.Models.Patient;

namespace WebApplication1;

public class AppDbContext : DbContext
{
    public DbSet<Doctor> Doctors { get; set; }
    public DbSet<Patient> Patients { get; set; }
    public DbSet<Medicament> Medicaments { get; set; }
    public DbSet<Prescription_Medicament> PrescriptionMedicaments { get; set; }
    public DbSet<Prescription> Prescriptions { get; set; }
    
    public DbSet<User> Users { get; set; }

    public AppDbContext()
    {
    }

    public AppDbContext(DbContextOptions options) : base(options)
    {
        
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfiguration(new DoctorEfConfiguration());
        modelBuilder.ApplyConfiguration(new PatientEfConfiguration());
        modelBuilder.ApplyConfiguration(new PrescriptionEfConfiguration());
        modelBuilder.ApplyConfiguration(new MedicationEfConfiguration());
        modelBuilder.ApplyConfiguration(new Prescription_MedicamentEfConfiguration());
        modelBuilder.ApplyConfiguration(new UserEfConf());
        
        modelBuilder.Entity<Doctor>().HasData(
            new Doctor { IdDoctor = 1, FirstName = "John", LastName = "Doe", Email = "john.doe@example.com" },
            new Doctor { IdDoctor = 2, FirstName = "Jane", LastName = "Smith", Email = "jane.smith@example.com" }
        );

        modelBuilder.Entity<Patient>().HasData(
            new Patient { IdPatient = 1, FirstName = "Alice", LastName = "Johnson", Birthdate = new DateTime(1980, 1, 1) },
            new Patient { IdPatient = 2, FirstName = "Bob", LastName = "Brown", Birthdate = new DateTime(1990, 2, 2) }
        );

        modelBuilder.Entity<Medicament>().HasData(
            new Medicament { IdMedicament = 1, Name = "Aspirin", Description = "Pain reliever", Type = "Tablet" },
            new Medicament { IdMedicament = 2, Name = "Amoxicillin", Description = "Antibiotic", Type = "Capsule" }
        );

        modelBuilder.Entity<Prescription>().HasData(
            new Prescription { IdPrescription = 1, Date = DateTime.Now, DueDate = DateTime.Now.AddMonths(1), IdDoctor = 1, IdPatient = 1 },
            new Prescription { IdPrescription = 2, Date = DateTime.Now, DueDate = DateTime.Now.AddMonths(1), IdDoctor = 2, IdPatient = 2 }
        );

        modelBuilder.Entity<Prescription_Medicament>().HasData(
            new Prescription_Medicament { IdPrescription = 1, IdMedicament = 1, Dose = 2, Details = "Take two tablets daily" },
            new Prescription_Medicament { IdPrescription = 2, IdMedicament = 2, Dose = 1, Details = "Take one capsule daily" }
        );
    }
}