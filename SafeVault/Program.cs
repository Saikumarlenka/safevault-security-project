using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using SafeVault;
using HttpResults = Microsoft.AspNetCore.Http.HttpResults;

var builder = WebApplication.CreateBuilder(args);

var databasePath = builder.Configuration["SafeVault:Database"] ?? "safevault.db";
var connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath }.ToString();
var repository = new SafeVaultRepository(connectionString);
builder.Services.AddSingleton(repository);
builder.Services.AddSingleton<IPasswordHasher<SafeVaultUser>, PasswordHasher<SafeVaultUser>>();
builder.Services.AddSingleton<ISafeVaultAuthService, SafeVaultAuthService>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "SafeVault.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
        options.Events.OnValidatePrincipal = context =>
        {
            var principal = context.Principal;
            var username = principal?.Identity?.Name;
            var role = principal?.FindFirst(ClaimTypes.Role)?.Value;
            var authService = context.HttpContext.RequestServices.GetRequiredService<ISafeVaultAuthService>();
            if (username is null || role is null || authService.GetRole(username) != role)
            {
                context.RejectPrincipal();
                return context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }

            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery();
builder.Services.AddOpenApi();

var app = builder.Build();
repository.Initialize();
ConfigureBootstrapAdmin(app.Configuration, app.Services.GetRequiredService<ISafeVaultAuthService>());

if (app.Environment.IsDevelopment())
    app.MapOpenApi();

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapGet("/", (HttpContext context, IAntiforgery antiforgery) =>
{
    var requestToken = HtmlEncoder.Default.Encode(
        antiforgery.GetAndStoreTokens(context).RequestToken ?? string.Empty);
    return Results.Content($$"""
    <!doctype html><html><body>
    <h1>SafeVault</h1>
    <form method="post" action="/users">
      <input type="hidden" name="__RequestVerificationToken" value="{{requestToken}}">
      <label>Username <input name="username" pattern="[A-Za-z0-9_]{3,50}" maxlength="50" required></label>
      <label>Email <input name="email" type="email" maxlength="254" required></label>
      <label>Password <input name="password" type="password" minlength="12" maxlength="128" required></label>
      <button type="submit">Create user</button>
    </form>
    </body></html>
    """, "text/html");
})
    .WithSummary("Displays account registration form");

app.MapPost("/users", (
    [FromForm] string username,
    [FromForm] string email,
    [FromForm] string password,
    ISafeVaultAuthService auth) =>
{
    if (!InputValidator.TryValidateUser(username, email, out var validationError))
        return Results.BadRequest(new { error = validationError });

    if (string.IsNullOrWhiteSpace(password) || password.Length < 12 || password.Length > 128)
        return Results.BadRequest(new { error = "Password must be between 12 and 128 characters." });

    if (!auth.Register(username, email, password))
        return Results.Conflict(new { error = "The username already exists." });

    return Results.Ok(new
    {
        username,
        email,
        safeUsername = HtmlEncoder.Default.Encode(username),
        safeEmail = HtmlEncoder.Default.Encode(email),
        role = UserRoles.User
    });
})
    .WithSummary("Registers a standard user account")
    .WithDescription("New registrations always receive the User role.")
    .Accepts<IFormCollection>("application/x-www-form-urlencoded")
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status409Conflict);

app.MapPost("/login", async Task<HttpResults.Results<HttpResults.Ok<AuthResponse>, HttpResults.UnauthorizedHttpResult, HttpResults.BadRequest<ProblemDetails>>> (
    LoginRequest request,
    HttpContext context,
    ISafeVaultAuthService auth) =>
{
    if (!InputValidator.TryValidateUsername(request.Username, out _) ||
        string.IsNullOrWhiteSpace(request.Password) ||
        request.Password.Length > 128)
    {
        return TypedResults.BadRequest(new ProblemDetails
        {
            Title = "Invalid login request",
            Status = StatusCodes.Status400BadRequest
        });
    }

    var user = auth.Authenticate(request.Username, request.Password);
    if (user is null)
        return TypedResults.Unauthorized();

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, user.Role)
    };
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity));

    return TypedResults.Ok(new AuthResponse(user.Username, user.Role));
})
    .WithSummary("Authenticates a user and issues a secure session cookie")
    .Produces<AuthResponse>(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status401Unauthorized);

app.MapPost("/logout", async Task<HttpResults.NoContent> (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return TypedResults.NoContent();
})
    .RequireAuthorization()
    .WithSummary("Ends the current authenticated session")
    .Produces(StatusCodes.Status204NoContent)
    .Produces(StatusCodes.Status401Unauthorized);

app.MapGet("/profile", (ClaimsPrincipal user) =>
        TypedResults.Ok(new AuthResponse(user.Identity!.Name!, user.FindFirstValue(ClaimTypes.Role)!)))
    .RequireAuthorization()
    .WithSummary("Returns the authenticated user's identity and role")
    .Produces<AuthResponse>(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status401Unauthorized);

app.MapGet("/admin/dashboard", () => TypedResults.Ok(new { message = "Admin dashboard" }))
    .RequireAuthorization(policy => policy.RequireRole(UserRoles.Admin))
    .WithSummary("Displays the administrator dashboard")
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status401Unauthorized)
    .Produces(StatusCodes.Status403Forbidden);

app.MapPut("/admin/users/{username}/role", HttpResults.Results<HttpResults.NoContent, HttpResults.BadRequest<ProblemDetails>, HttpResults.NotFound> (
    string username,
    AssignRoleRequest request,
    ISafeVaultAuthService auth) =>
{
    if (!InputValidator.TryValidateUsername(username, out _) ||
        request.Role is not UserRoles.User and not UserRoles.Admin)
    {
        return TypedResults.BadRequest(new ProblemDetails
        {
            Title = "Username or role is invalid",
            Status = StatusCodes.Status400BadRequest
        });
    }

    return auth.AssignRole(username, request.Role)
        ? TypedResults.NoContent()
        : TypedResults.NotFound();
})
    .RequireAuthorization(policy => policy.RequireRole(UserRoles.Admin))
    .WithSummary("Assigns a User or Admin role to an account")
    .Produces(StatusCodes.Status204NoContent)
    .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status401Unauthorized)
    .Produces(StatusCodes.Status403Forbidden)
    .Produces(StatusCodes.Status404NotFound);

app.Run();

static void ConfigureBootstrapAdmin(IConfiguration configuration, ISafeVaultAuthService auth)
{
    var username = configuration["SafeVault:BootstrapAdmin:Username"];
    var email = configuration["SafeVault:BootstrapAdmin:Email"];
    var password = configuration["SafeVault:BootstrapAdmin:Password"];
    if (username is null && email is null && password is null)
        return;

    if (username is null || email is null || password is null)
        throw new InvalidOperationException("Bootstrap admin username, email, and password must all be configured.");

    var currentRole = auth.GetRole(username);
    if (currentRole is not null)
    {
        if (currentRole != UserRoles.Admin)
            throw new InvalidOperationException("The configured bootstrap account already exists without the Admin role.");
        return;
    }

    if (!auth.CreateBootstrapAdmin(username, email, password))
        throw new InvalidOperationException("The bootstrap admin account could not be created. Check its configured values.");
}

public partial class Program { }

public static partial class InputValidator
{
    [GeneratedRegex(@"^[A-Za-z0-9_]{3,50}$", RegexOptions.CultureInvariant)]
    private static partial Regex UsernamePattern();

    [GeneratedRegex(@"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex EmailPattern();

    public static bool TryValidateUsername(string? username, out string error)
    {
        if (string.IsNullOrWhiteSpace(username) || !UsernamePattern().IsMatch(username))
        {
            error = "Username must be 3-50 characters and contain only letters, numbers, and underscores.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    public static bool TryValidateUser(string? username, string? email, out string error)
    {
        if (!TryValidateUsername(username, out error))
            return false;

        if (string.IsNullOrWhiteSpace(email) || email.Length > 254 || !EmailPattern().IsMatch(email))
        {
            error = "A valid email address is required.";
            return false;
        }

        error = string.Empty;
        return true;
    }
}
