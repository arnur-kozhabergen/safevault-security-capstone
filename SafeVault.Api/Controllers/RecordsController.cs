using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Api.Data;
using SafeVault.Api.Models;

namespace SafeVault.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/records")]
public sealed class RecordsController(SafeVaultDbContext database) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<VaultRecordResponse>>> Search(
        [FromQuery] string? title,
        [FromQuery] int limit = 20,
        [FromQuery] int offset = 0,
        CancellationToken cancellationToken = default)
    {
        if (title is { Length: > 100 } || limit is < 1 or > 100 || offset is < 0 or > 100_000)
        {
            return BadRequest(new ProblemDetails { Title = "Invalid search parameters." });
        }

        var query = VisibleRecords();
        if (!string.IsNullOrEmpty(title))
        {
            // EF Core sends the user value as a SQL parameter; it is never concatenated into SQL text.
            query = query.Where(record => record.Title == title);
        }

        var records = await query
            .OrderBy(record => record.CreatedUtc)
            .ThenBy(record => record.Id)
            .Skip(offset)
            .Take(limit)
            .Select(record => new VaultRecordResponse(record.Id, record.Title, record.Body, record.CreatedUtc))
            .ToListAsync(cancellationToken);

        return Ok(records);
    }

    [HttpPost]
    public async Task<ActionResult<VaultRecordResponse>> Create(
        CreateRecordRequest request,
        CancellationToken cancellationToken = default)
    {
        var ownerId = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (string.IsNullOrWhiteSpace(ownerId))
        {
            return Unauthorized();
        }

        var record = new VaultRecord
        {
            OwnerId = ownerId,
            Title = request.Title.Trim(),
            Body = request.Body,
            CreatedUtc = DateTimeOffset.UtcNow
        };

        database.Records.Add(record);
        await database.SaveChangesAsync(cancellationToken);

        var response = ToResponse(record);
        return CreatedAtAction(nameof(GetById), new { id = record.Id }, response);
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<VaultRecordResponse>> GetById(Guid id, CancellationToken cancellationToken = default)
    {
        var record = await VisibleRecords().SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        return record is null ? NotFound() : Ok(ToResponse(record));
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken cancellationToken = default)
    {
        var record = await VisibleRecords().SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (record is null)
        {
            return NotFound();
        }

        database.Records.Remove(record);
        await database.SaveChangesAsync(cancellationToken);
        return NoContent();
    }

    [HttpGet("{id:guid}/preview")]
    [Produces("text/html")]
    public async Task<IActionResult> Preview(Guid id, CancellationToken cancellationToken = default)
    {
        var record = await VisibleRecords().SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (record is null)
        {
            return NotFound();
        }

        Response.Headers["Content-Security-Policy"] = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
        var safeTitle = HtmlEncoder.Default.Encode(record.Title);
        var safeBody = HtmlEncoder.Default.Encode(record.Body);
        var html = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Vault record</title><body><main><h1>"
            + safeTitle + "</h1><p>" + safeBody + "</p></main></body></html>";

        return Content(html, "text/html; charset=utf-8");
    }

    private IQueryable<VaultRecord> VisibleRecords()
    {
        var query = database.Records.AsNoTracking();
        if (User.IsInRole("Admin"))
        {
            return query;
        }

        var ownerId = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        return string.IsNullOrWhiteSpace(ownerId)
            ? query.Where(_ => false)
            : query.Where(record => record.OwnerId == ownerId);
    }

    private static VaultRecordResponse ToResponse(VaultRecord record) =>
        new(record.Id, record.Title, record.Body, record.CreatedUtc);
}

