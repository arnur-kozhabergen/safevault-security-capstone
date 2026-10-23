using System.Net;
using System.Net.Http.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SafeVault.Api.Models;

namespace SafeVault.Api.Tests;

[TestClass]
public sealed class SecurityRegressionTests
{
    [TestMethod]
    public async Task Protected_endpoint_rejects_missing_bearer_token()
    {
        await using var host = await SafeVaultTestHost.CreateAsync();
        using var response = await host.AnonymousClient.GetAsync("/api/records");

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [TestMethod]
    public async Task User_scope_and_sql_parameterization_block_cross_user_reads_and_injection()
    {
        await using var host = await SafeVaultTestHost.CreateAsync();
        using var alice = await host.RegisterAndAuthenticateAsync("alice@example.test");
        var aliceRecord = await CreateRecordAsync(alice, "Alice secret", "Alice body");

        using var bob = await host.RegisterAndAuthenticateAsync("bob@example.test");
        var bobRecord = await CreateRecordAsync(bob, "Bob private", "Bob body");

        using var directRead = await alice.GetAsync($"/api/records/{bobRecord.Id}");
        Assert.AreEqual(HttpStatusCode.NotFound, directRead.StatusCode);

        using var otherUserSearch = await alice.GetAsync("/api/records?title=Bob%20private");
        otherUserSearch.EnsureSuccessStatusCode();
        var otherUserResults = await otherUserSearch.Content.ReadFromJsonAsync<List<VaultRecordResponse>>();
        Assert.AreEqual(0, otherUserResults?.Count);

        using var injectionSearch = await alice.GetAsync("/api/records?title=%27%20OR%201%3D1--");
        injectionSearch.EnsureSuccessStatusCode();
        var injectionResults = await injectionSearch.Content.ReadFromJsonAsync<List<VaultRecordResponse>>();
        Assert.AreEqual(0, injectionResults?.Count);

        using var ownRead = await alice.GetAsync($"/api/records/{aliceRecord.Id}");
        Assert.AreEqual(HttpStatusCode.OK, ownRead.StatusCode);
    }

    [TestMethod]
    public async Task Admin_route_requires_admin_role()
    {
        await using var host = await SafeVaultTestHost.CreateAsync();
        using var regularUser = await host.RegisterAndAuthenticateAsync("member@example.test");

        using var denied = await regularUser.GetAsync("/api/admin/records");
        Assert.AreEqual(HttpStatusCode.Forbidden, denied.StatusCode);

        await host.AddRoleAsync("member@example.test", "Admin");
        using var admin = await host.LoginAsync("member@example.test");
        using var allowed = await admin.GetAsync("/api/admin/records");
        Assert.AreEqual(HttpStatusCode.OK, allowed.StatusCode);
    }

    [TestMethod]
    public async Task Html_preview_encodes_user_markup_and_sets_security_headers()
    {
        await using var host = await SafeVaultTestHost.CreateAsync();
        using var user = await host.RegisterAndAuthenticateAsync("xss@example.test");
        var record = await CreateRecordAsync(user, "<script>alert(1)</script>", "<img src=x onerror=alert(1)>");

        using var response = await user.GetAsync($"/api/records/{record.Id}/preview");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();

        Assert.AreEqual("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.IsFalse(html.Contains("<script>", StringComparison.OrdinalIgnoreCase));
        Assert.IsTrue(html.Contains("&lt;script&gt;", StringComparison.Ordinal));
        Assert.IsTrue(response.Headers.Contains("Content-Security-Policy"));
        Assert.IsTrue(response.Headers.Contains("X-Content-Type-Options"));
    }

    [TestMethod]
    public async Task Invalid_record_input_is_rejected()
    {
        await using var host = await SafeVaultTestHost.CreateAsync();
        using var user = await host.RegisterAndAuthenticateAsync("validation@example.test");

        using var response = await user.PostAsJsonAsync("/api/records", new { Title = " ", Body = "valid body" });
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [TestMethod]
    public async Task Five_failed_logins_lock_out_even_the_correct_password()
    {
        // Copilot suggested this regression; adapted to the actual generic-401 API contract.
        await using var host = await SafeVaultTestHost.CreateAsync();
        const string email = "lockout@example.test";
        using var registered = await host.RegisterAndAuthenticateAsync(email);
        for (var attempt = 0; attempt < 5; attempt++)
        {
            using var failed = await host.AnonymousClient.PostAsJsonAsync("/api/auth/login",
                new { Email = email, Password = "WrongPassword123!" });
            Assert.AreEqual(HttpStatusCode.Unauthorized, failed.StatusCode);
        }
        using var correctButLocked = await host.AnonymousClient.PostAsJsonAsync("/api/auth/login",
            new { Email = email, Password = "SafeVaultPassword123!" });
        Assert.AreEqual(HttpStatusCode.Unauthorized, correctButLocked.StatusCode);
    }

    [TestMethod]
    public async Task Invalid_or_tampered_jwt_cannot_gain_admin_access()
    {
        await using var host = await SafeVaultTestHost.CreateAsync();
        using var user = await host.RegisterAndAuthenticateAsync("forgery@example.test");
        var token = user.DefaultRequestHeaders.Authorization!.Parameter!;
        var segments = token.Split('.');
        var payload = System.Text.Encoding.UTF8.GetString(
            Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(segments[1]));
        Assert.IsTrue(payload.Contains("\"role\":\"User\"", StringComparison.Ordinal));
        segments[1] = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            payload.Replace("\"role\":\"User\"", "\"role\":\"Admin\"", StringComparison.Ordinal));
        foreach (var invalid in new[] { "not-a-real.jwt.token", string.Join('.', segments) })
        {
            user.DefaultRequestHeaders.Authorization = new("Bearer", invalid);
            using var response = await user.GetAsync("/api/admin/records");
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    [TestMethod]
    public async Task Registration_ignores_client_supplied_privileged_role()
    {
        await using var host = await SafeVaultTestHost.CreateAsync();
        using var registration = await host.AnonymousClient.PostAsJsonAsync("/api/auth/register",
            new { Email = "role-injection@example.test", Password = "SafeVaultPassword123!", Role = "Admin", Roles = new[] { "Admin" } });
        Assert.AreEqual(HttpStatusCode.Created, registration.StatusCode);
        using var user = await host.LoginAsync("role-injection@example.test");
        using var response = await user.GetAsync("/api/admin/records");
        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [TestMethod]
    public async Task Revoked_admin_role_is_denied_even_with_unexpired_admin_token()
    {
        await using var host = await SafeVaultTestHost.CreateAsync();
        const string email = "revocation@example.test";
        using var ordinary = await host.RegisterAndAuthenticateAsync(email);
        await host.AddRoleAsync(email, "Admin");
        using var admin = await host.LoginAsync(email);
        using var before = await admin.GetAsync("/api/admin/records");
        Assert.AreEqual(HttpStatusCode.OK, before.StatusCode);
        await host.RemoveRoleAsync(email, "Admin");
        using var after = await admin.GetAsync("/api/admin/records");
        Assert.AreEqual(HttpStatusCode.Forbidden, after.StatusCode);
    }

    private static async Task<VaultRecordResponse> CreateRecordAsync(HttpClient client, string title, string body)
    {
        using var response = await client.PostAsJsonAsync("/api/records", new { Title = title, Body = body });
        Assert.AreEqual(HttpStatusCode.Created, response.StatusCode, await response.Content.ReadAsStringAsync());
        return await response.Content.ReadFromJsonAsync<VaultRecordResponse>()
            ?? throw new InvalidOperationException("Create response did not contain a record.");
    }
}

