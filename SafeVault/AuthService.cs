using Microsoft.AspNetCore.Identity;

namespace SafeVault;

public static class UserRoles
{
    public const string User = "User";
    public const string Admin = "Admin";
}

public interface ISafeVaultAuthService
{
    bool Register(string username, string email, string password);
    SafeVaultUser? Authenticate(string username, string password);
    bool AssignRole(string username, string role);
    string? GetRole(string username);
    bool CreateBootstrapAdmin(string username, string email, string password);
}

public sealed class SafeVaultAuthService(
    SafeVaultRepository repository,
    IPasswordHasher<SafeVaultUser> passwordHasher) : ISafeVaultAuthService
{
    public bool Register(string username, string email, string password) =>
        CreateUser(username, email, password, UserRoles.User);

    public SafeVaultUser? Authenticate(string username, string password)
    {
        var user = repository.FindByUsername(username);
        if (user is null || string.IsNullOrEmpty(user.PasswordHash))
            return null;

        var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
        if (result == PasswordVerificationResult.Failed)
            return null;

        if (result == PasswordVerificationResult.SuccessRehashNeeded)
        {
            var updatedHash = passwordHasher.HashPassword(user, password);
            repository.UpdatePasswordHash(user.Id, updatedHash);
        }

        return user;
    }

    public bool AssignRole(string username, string role)
    {
        if (role is not UserRoles.User and not UserRoles.Admin)
            return false;

        return repository.UpdateRole(username, role);
    }

    public string? GetRole(string username) => repository.FindByUsername(username)?.Role;

    public bool CreateBootstrapAdmin(string username, string email, string password) =>
        CreateUser(username, email, password, UserRoles.Admin);

    private bool CreateUser(string username, string email, string password, string role)
    {
        if (!InputValidator.TryValidateUser(username, email, out _) ||
            string.IsNullOrWhiteSpace(password) ||
            password.Length < 12 ||
            password.Length > 128)
        {
            return false;
        }

        var user = new SafeVaultUser(0, username, email, string.Empty, role);
        var passwordHash = passwordHasher.HashPassword(user, password);
        return repository.AddUser(username, email, passwordHash, role);
    }
}
