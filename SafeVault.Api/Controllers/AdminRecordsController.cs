using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Api.Data;
using SafeVault.Api.Models;

namespace SafeVault.Api.Controllers;

[ApiController]
[Authorize(Roles = "Admin")]
[Route("api/admin/records")]
public sealed class AdminRecordsController(SafeVaultDbContext database) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<VaultRecordResponse>>> GetAll(CancellationToken cancellationToken = default)
    {
        var records = await database.Records
            .AsNoTracking()
            .OrderBy(record => record.CreatedUtc)
            .ThenBy(record => record.Id)
            .Select(record => new VaultRecordResponse(record.Id, record.Title, record.Body, record.CreatedUtc))
            .ToListAsync(cancellationToken);

        return Ok(records);
    }
}
