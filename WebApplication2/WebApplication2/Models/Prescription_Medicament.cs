namespace WebApplication1.Models;

public class Prescription_Medicament
{
    public int IdPrescription { get; set; }
    public int IdMedicament { get; set; }
    public virtual Prescription Prescription { get; set; }
    public virtual Medicament Medicament { get; set; }
    public int Dose { get; set; }
    public string Details { get; set; }
}