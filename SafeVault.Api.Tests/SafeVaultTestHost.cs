using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SafeVault.Api.Data;

namespace SafeVault.Api.Tests;

public sealed class SafeVaultApiFactory(SqliteConnection connection) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SigningKey"] = "test-only-key-with-at-least-32-bytes-123456",
                ["Jwt:Issuer"] = "SafeVault.Tests",
                ["Jwt:Audience"] = "SafeVault.Tests"
            });
        });
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<DbContextOptions<SafeVaultDbContext>>();
            services.AddDbContext<SafeVaultDbContext>(options => options.UseSqlite(connection));
        });
    }
}

public sealed class SafeVaultTestHost : IAsyncDisposable
{
    private readonly SqliteConnection _connection;
    private readonly SafeVaultApiFactory _factory;

    private SafeVaultTestHost(SqliteConnection connection, SafeVaultApiFactory factory)
    {
        _connection = connection;
        _factory = factory;
        AnonymousClient = CreateClient();
    }

    public HttpClient AnonymousClient { get; }
    public IServiceProvider Services => _factory.Services;

    public static async Task<SafeVaultTestHost> CreateAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var factory = new SafeVaultApiFactory(connection);
        return new SafeVaultTestHost(connection, factory);
    }

    public HttpClient CreateClient() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false
    });

    public async Task<HttpClient> RegisterAndAuthenticateAsync(string email, string password = "SafeVaultPassword123!")
    {
        using var registrationClient = CreateClient();
        using var registration = await registrationClient.PostAsJsonAsync("/api/auth/register", new { Email = email, Password = password });
        if (registration.StatusCode != System.Net.HttpStatusCode.Created)
        {
            throw new InvalidOperationException($"Test user registration failed: {(int)registration.StatusCode} {await registration.Content.ReadAsStringAsync()}");
        }

        return await LoginAsync(email, password);
    }

    public async Task<HttpClient> LoginAsync(string email, string password = "SafeVaultPassword123!")
    {
        using var loginClient = CreateClient();
        using var response = await loginClient.PostAsJsonAsync("/api/auth/login", new { Email = email, Password = password });
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenEnvelope>()
            ?? throw new InvalidOperationException("Login response did not contain a token.");

        var authenticatedClient = CreateClient();
        authenticatedClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token.AccessToken);
        return authenticatedClient;
    }

    public async Task AddRoleAsync(string email, string role)
    {
        await using var scope = Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<SafeVault.Api.Models.SafeVaultUser>>();
        var user = await users.FindByEmailAsync(email) ?? throw new InvalidOperationException("Test user was not found.");
        var result = await users.AddToRoleAsync(user, role);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException("Could not add the test role.");
        }
    }

    public async Task RemoveRoleAsync(string email, string role)
    {
        await using var scope = Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<SafeVault.Api.Models.SafeVaultUser>>();
        var user = await users.FindByEmailAsync(email) ?? throw new InvalidOperationException("Test user was not found.");
        var result = await users.RemoveFromRoleAsync(user, role);
        if (!result.Succeeded) throw new InvalidOperationException("Could not remove the test role.");
    }

    public async ValueTask DisposeAsync()
    {
        AnonymousClient.Dispose();
        _factory.Dispose();
        await _connection.DisposeAsync();
    }

    private sealed record TokenEnvelope(string AccessToken, string TokenType, DateTime ExpiresAtUtc);
}

