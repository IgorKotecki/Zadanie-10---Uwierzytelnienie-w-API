using Microsoft.AspNetCore.Mvc;
using WebApplication1.DTO;

namespace WebApplication1.Controllers;
[Route("/api/[controller]")]
[ApiController]
public class PrescriptionController : ControllerBase
{
    private readonly AppDbContext _context;

    public PrescriptionController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<PrescriptionDTO>> GetPrescription(int id)
    {
        var pres =  _context.Prescriptions.Where(p => p.IdPrescription == id).Select(p => new PrescriptionDTO()
        {
            IdPrescription = p.IdPrescription,
            Date = p.Date,
            DueDate = p.DueDate,
            Doctor = new DoctorDTO
            {
                IdDoctor = p.Doctor.IdDoctor, FirstName = p.Doctor.FirstName, LastName = p.Doctor.LastName,
                Email = p.Doctor.Email
            },
            Patient = new PatientDTO
            {
                IdPatient = p.Patient.IdPatient, FirstName = p.Patient.FirstName, LastName = p.Patient.LastName,
                Birthdate = p.Patient.Birthdate
            },
            Medicaments = p.PrescriptionMedicaments.Select(Pm => new MedicationDTO
            {
                IdMedicament = Pm.Medicament.IdMedicament,
                Name = Pm.Medicament.Name,
                Description = Pm.Medicament.Description,
                Type = Pm.Medicament.Type
            }).ToList()
        }).FirstOrDefault();

        if (pres == null)
            return NoContent();

        return Ok(pres);
    }
}