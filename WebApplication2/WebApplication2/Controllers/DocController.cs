using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Models;

namespace WebApplication1.Controllers;

[Route("/api/[controller]")]
[ApiController]
public class DocController : ControllerBase
{
    private readonly AppDbContext _context;

    public DocController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public ActionResult<IEnumerable<Doctor>> GetDocsAsync()
    {
        var docs = _context.Doctors.ToList();

        return docs;
    }

    [HttpGet("{id}")]
    public ActionResult<Doctor> GetDoc(int id)
    {
        var doc = _context.Doctors.FirstOrDefault(d => d.IdDoctor == id);
        
        if (doc == null)
            return NotFound();
        
        return doc;
    }

    [HttpPost]
    public ActionResult<Doctor> AddDoc(Doctor doc)
    {
        _context.Doctors.Add(doc);
        _context.SaveChanges();

        return CreatedAtAction(nameof(GetDoc), new { id = doc.IdDoctor }, doc);
    }

    [HttpPut("{id}")]
    public IActionResult ModyfyDoc(int id,Doctor doc)
    {
        if (id != doc.IdDoctor)
        {
            return BadRequest();
        }

        var existingDoc = _context.Doctors.FirstOrDefault(d => d.IdDoctor == id);
        
        if (existingDoc == null)
            return NotFound();

        existingDoc.FirstName = doc.FirstName;
        existingDoc.LastName = doc.LastName;
        existingDoc.Email = doc.Email;

        _context.SaveChanges();
        
        return NoContent();
    }

    [HttpDelete("{id}")]
    public IActionResult DeleteDoc(int id)
    {
        var doc = _context.Doctors.FirstOrDefault(d => d.IdDoctor == id);

        if (doc == null)
            return NotFound();

        _context.Doctors.Remove(doc);
        _context.SaveChanges();

        return NoContent();
    }
}