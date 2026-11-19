using System.ComponentModel.DataAnnotations;

namespace SafeVault;

/// <summary>Credentials submitted to start a SafeVault session.</summary>
public sealed record LoginRequest
{
    [Required, StringLength(50, MinimumLength = 3)]
    public required string Username { get; init; }

    [Required, StringLength(128, MinimumLength = 12)]
    public required string Password { get; init; }
}

/// <summary>Role to assign to an existing account.</summary>
public sealed record AssignRoleRequest
{
    [Required]
    public required string Role { get; init; }
}

/// <summary>Authenticated account identity returned by SafeVault.</summary>
public sealed record AuthResponse(string Username, string Role);
