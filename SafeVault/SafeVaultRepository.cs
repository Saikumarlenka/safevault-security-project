using Microsoft.Data.Sqlite;

namespace SafeVault;

public sealed record SafeVaultUser(int Id, string Username, string Email, string PasswordHash, string Role);

public sealed class SafeVaultRepository(string connectionString)
{
    public void Initialize()
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Email TEXT NOT NULL,
                PasswordHash TEXT NOT NULL DEFAULT '',
                Role TEXT NOT NULL DEFAULT 'User'
            );
            """;
        command.ExecuteNonQuery();

        EnsureColumn(connection, "PasswordHash", "TEXT NOT NULL DEFAULT ''");
        EnsureColumn(connection, "Role", "TEXT NOT NULL DEFAULT 'User'");
    }

    public bool AddUser(string username, string email, string passwordHash, string role)
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES ($username, $email, $passwordHash, $role)
            """;
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$passwordHash", passwordHash);
        command.Parameters.AddWithValue("$role", role);

        try
        {
            command.ExecuteNonQuery();
            return true;
        }
        catch (SqliteException exception) when (exception.SqliteExtendedErrorCode == 2067)
        {
            return false;
        }
    }

    public SafeVaultUser? FindByUsername(string username)
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Id, Username, Email, PasswordHash, Role
            FROM Users WHERE Username = $username
            """;
        command.Parameters.AddWithValue("$username", username);
        using var reader = command.ExecuteReader();
        return reader.Read()
            ? new SafeVaultUser(
                reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4))
            : null;
    }

    public bool UpdatePasswordHash(int id, string passwordHash)
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET PasswordHash = $passwordHash WHERE Id = $id";
        command.Parameters.AddWithValue("$passwordHash", passwordHash);
        command.Parameters.AddWithValue("$id", id);
        return command.ExecuteNonQuery() == 1;
    }

    public bool UpdateRole(string username, string role)
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE Users SET Role = $role WHERE Username = $username";
        command.Parameters.AddWithValue("$role", role);
        command.Parameters.AddWithValue("$username", username);
        return command.ExecuteNonQuery() == 1;
    }

    private static void EnsureColumn(SqliteConnection connection, string columnName, string definition)
    {
        var exists = false;
        using (var check = connection.CreateCommand())
        {
            check.CommandText = "PRAGMA table_info(Users)";
            using var reader = check.ExecuteReader();
            while (reader.Read())
            {
                if (string.Equals(reader.GetString(1), columnName, StringComparison.OrdinalIgnoreCase))
                {
                    exists = true;
                    break;
                }
            }
        }

        if (exists)
            return;

        using var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE Users ADD COLUMN {columnName} {definition}";
        alter.ExecuteNonQuery();
    }
}
