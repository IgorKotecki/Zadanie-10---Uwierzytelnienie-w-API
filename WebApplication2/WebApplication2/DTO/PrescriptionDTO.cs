namespace WebApplication1.DTO;

public class PrescriptionDTO
{
    public int IdPrescription { get; set; }
    public DateTime Date { get; set; }
    public DateTime DueDate { get; set; }
    public DoctorDTO Doctor { get; set; }
    public PatientDTO Patient { get; set; }
    public List<MedicationDTO> Medicaments { get; set; }
}