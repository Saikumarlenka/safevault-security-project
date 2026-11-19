using System.Text.Encodings.Web;
using Microsoft.Data.Sqlite;
using SafeVault;

namespace SafeVault.Tests;

public class SecurityTests
{
    [Theory]
    [InlineData("admin' OR '1'='1")]
    [InlineData("<script>alert('xss')</script>")]
    [InlineData("valid user")]
    [InlineData("a")]
    public void RejectsInvalidUsernames(string username)
    {
        Assert.False(InputValidator.TryValidateUser(username, "safe@example.com", out _));
    }

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("name@example.com<script>")]
    [InlineData("")]
    public void RejectsInvalidEmails(string email)
    {
        Assert.False(InputValidator.TryValidateUser("safe_user", email, out _));
    }

    [Fact]
    public void AcceptsValidInput()
    {
        Assert.True(InputValidator.TryValidateUser("safe_user", "safe@example.com", out var error));
        Assert.Equal(string.Empty, error);
    }

    [Fact]
    public void SqlInjectionIsTreatedAsLiteralData()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        using (var setup = connection.CreateCommand())
        {
            setup.CommandText = "CREATE TABLE Users (Username TEXT, Email TEXT); INSERT INTO Users VALUES ('alice', 'alice@example.com')";
            setup.ExecuteNonQuery();
        }

        var attack = "alice' OR '1'='1";
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Email FROM Users WHERE Username = $username";
        command.Parameters.AddWithValue("$username", attack);

        Assert.Null(command.ExecuteScalar());
        Assert.Equal("alice@example.com",
            connection.CreateCommandWithParameter("SELECT Email FROM Users WHERE Username = $username", "$username", "alice").ExecuteScalar());
    }

    [Theory]
    [InlineData("<script>alert('xss')</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    public void HtmlEncodingNeutralizesXssPayloads(string payload)
    {
        var encoded = HtmlEncoder.Default.Encode(payload);

        Assert.DoesNotContain("<script", encoded, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", encoded, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("&lt;", encoded, StringComparison.Ordinal);
    }
}

internal static class SqliteCommandExtensions
{
    public static SqliteCommand CreateCommandWithParameter(
        this SqliteConnection connection,
        string sql,
        string name,
        object value)
    {
        var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue(name, value);
        return command;
    }
}
