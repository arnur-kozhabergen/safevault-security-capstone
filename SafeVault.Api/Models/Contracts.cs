using System.ComponentModel.DataAnnotations;

namespace SafeVault.Api.Models;

public sealed record RegisterRequest(
    [Required]
    [EmailAddress]
    [StringLength(254)]
    string Email,
    [Required]
    [MinLength(12)]
    [MaxLength(128)]
    string Password);

public sealed record LoginRequest(
    [Required]
    [EmailAddress]
    [StringLength(254)]
    string Email,
    [Required]
    [MaxLength(128)]
    string Password);

public sealed record AccessTokenResponse(string AccessToken, string TokenType, DateTime ExpiresAtUtc);

public sealed record CreateRecordRequest(
    [Required]
    [StringLength(100, MinimumLength = 1)]
    string Title,
    [Required]
    [StringLength(4000, MinimumLength = 1)]
    string Body) : IValidatableObject
{
    // Adapted from the actual GitHub Copilot review: validate content after normalization.
    // SQL parameters and output encoding remain separate defenses.
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (string.IsNullOrWhiteSpace(Title) || Title.Trim().Length > 100)
            yield return new ValidationResult("Title must contain 1-100 characters after trimming.", [nameof(Title)]);
        if (string.IsNullOrWhiteSpace(Body) || Body.Length > 4000)
            yield return new ValidationResult("Body must contain 1-4000 nonblank characters.", [nameof(Body)]);
    }
}

public sealed record VaultRecordResponse(Guid Id, string Title, string Body, DateTimeOffset CreatedUtc);

