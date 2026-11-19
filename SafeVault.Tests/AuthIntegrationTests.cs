using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SafeVault;

namespace SafeVault.Tests;

public sealed class AuthIntegrationTests
{
    [Fact]
    public async Task LoginRejectsWrongPasswordAndAdminRequiresAuthentication()
    {
        using var factory = new SafeVaultFactory();
        using var client = factory.CreateHttpsClient();

        var anonymousResponse = await client.GetAsync("/admin/dashboard");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

        var loginResponse = await client.PostAsJsonAsync("/login",
            new LoginRequest { Username = "AdminOne", Password = "incorrect-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, loginResponse.StatusCode);
    }

    [Fact]
    public async Task StandardUserCanLoginButCannotAccessAdminDashboard()
    {
        using var factory = new SafeVaultFactory();
        using var client = factory.CreateHttpsClient();

        var registration = await RegisterUser(client, "RegularUser", "regular@example.com");
        Assert.True(registration.StatusCode == HttpStatusCode.OK,
            $"Registration failed with {(int)registration.StatusCode}: {await registration.Content.ReadAsStringAsync()}");
        AssertStoredPasswordIsHashed(factory.DatabasePath, "RegularUser", "UserPassword!123");

        var login = await client.PostAsJsonAsync("/login",
            new LoginRequest { Username = "RegularUser", Password = "UserPassword!123" });
        Assert.True(login.StatusCode == HttpStatusCode.OK,
            $"Login failed with {(int)login.StatusCode}: {await login.Content.ReadAsStringAsync()}");
        var cookie = Assert.Single(login.Headers.GetValues("Set-Cookie"));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);

        var profile = await client.GetAsync("/profile");
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode);
        var dashboard = await client.GetAsync("/admin/dashboard");
        Assert.Equal(HttpStatusCode.Forbidden, dashboard.StatusCode);
    }

    [Fact]
    public async Task AdminCanAssignRolesAndRoleChangesInvalidateExistingSessions()
    {
        using var factory = new SafeVaultFactory();
        using var adminClient = factory.CreateHttpsClient();
        using var userClient = factory.CreateHttpsClient();

        var adminLogin = await adminClient.PostAsJsonAsync("/login",
            new LoginRequest { Username = "AdminOne", Password = "BootstrapAdmin!123" });
        Assert.True(adminLogin.StatusCode == HttpStatusCode.OK,
            $"Admin login failed with {(int)adminLogin.StatusCode}: {await adminLogin.Content.ReadAsStringAsync()}");

        var registration = await RegisterUser(adminClient, "NewUser", "newuser@example.com");
        Assert.True(registration.StatusCode == HttpStatusCode.OK,
            $"Registration failed with {(int)registration.StatusCode}: {await registration.Content.ReadAsStringAsync()}");

        var userLogin = await userClient.PostAsJsonAsync("/login",
            new LoginRequest { Username = "NewUser", Password = "UserPassword!123" });
        Assert.Equal(HttpStatusCode.OK, userLogin.StatusCode);

        var deniedRoleChange = await userClient.PutAsJsonAsync("/admin/users/NewUser/role",
            new AssignRoleRequest { Role = UserRoles.Admin });
        Assert.Equal(HttpStatusCode.Forbidden, deniedRoleChange.StatusCode);

        var roleChange = await adminClient.PutAsJsonAsync("/admin/users/NewUser/role",
            new AssignRoleRequest { Role = UserRoles.Admin });
        Assert.Equal(HttpStatusCode.NoContent, roleChange.StatusCode);

        var oldSession = await userClient.GetAsync("/profile");
        Assert.Equal(HttpStatusCode.Unauthorized, oldSession.StatusCode);

        var relogin = await userClient.PostAsJsonAsync("/login",
            new LoginRequest { Username = "NewUser", Password = "UserPassword!123" });
        Assert.Equal(HttpStatusCode.OK, relogin.StatusCode);
        var dashboard = await userClient.GetAsync("/admin/dashboard");
        Assert.Equal(HttpStatusCode.OK, dashboard.StatusCode);
    }

    [Fact]
    public void InitializationMigratesActivityOneUserTable()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"safevault-migration-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString();
        try
        {
            using (var connection = new SqliteConnection(connectionString))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE Users (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        Username TEXT NOT NULL UNIQUE,
                        Email TEXT NOT NULL
                    );
                    INSERT INTO Users (Username, Email) VALUES ('OldUser', 'old@example.com');
                    """;
                command.ExecuteNonQuery();
            }

            var repository = new SafeVaultRepository(connectionString);
            repository.Initialize();
            var migratedUser = repository.FindByUsername("OldUser");

            Assert.NotNull(migratedUser);
            Assert.Equal(string.Empty, migratedUser.PasswordHash);
            Assert.Equal(UserRoles.User, migratedUser.Role);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath))
                File.Delete(databasePath);
        }
    }

    private static async Task<HttpResponseMessage> RegisterUser(HttpClient client, string username, string email)
    {
        var page = await client.GetStringAsync("/");
        var token = Regex.Match(page,
            "name=\"__RequestVerificationToken\" value=\"([^\"]+)\"").Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token));

        return await client.PostAsync("/users", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = username,
            ["email"] = email,
            ["password"] = "UserPassword!123",
            ["__RequestVerificationToken"] = token
        }));
    }

    private static void AssertStoredPasswordIsHashed(string databasePath, string username, string password)
    {
        var repository = new SafeVaultRepository(
            new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString());
        var user = repository.FindByUsername(username);

        Assert.NotNull(user);
        Assert.NotEqual(password, user.PasswordHash);
    }

    private sealed class SafeVaultFactory : WebApplicationFactory<Program>
    {
        public string DatabasePath { get; } =
            Path.Combine(Path.GetTempPath(), $"safevault-tests-{Guid.NewGuid():N}.db");

        public HttpClient CreateHttpsClient() =>
            CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false
            });

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("SafeVault:Database", DatabasePath);
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SafeVault:Database"] = DatabasePath,
                    ["SafeVault:BootstrapAdmin:Username"] = "AdminOne",
                    ["SafeVault:BootstrapAdmin:Email"] = "admin@example.com",
                    ["SafeVault:BootstrapAdmin:Password"] = "BootstrapAdmin!123"
                });
            });
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                SqliteConnection.ClearAllPools();
                if (File.Exists(DatabasePath))
                    File.Delete(DatabasePath);
            }
        }
    }
}
