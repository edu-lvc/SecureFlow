# Secure Coding in C# and ASP.NET Core

This reference targets modern ASP.NET Core on .NET 8, 9, and 10. It is the first deeply validated
ecosystem for SecureFlow. Prefer framework features over custom implementations, and keep the
enforcement point on the server.

## Project and configuration baseline

```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>
</Project>
```

- Pin package versions and commit lock files where the ecosystem supports them.
- Do not commit `appsettings.Production.json` with real values.
- Use user-secrets locally: `dotnet user-secrets set "ExternalApi:ApiKey" "<value>"`.
- Use a managed identity or vault in production; do not copy secrets into environment files in
  the repository.
- Disable detailed exception pages outside Development.

## Input validation

### Preferred: API controller with data annotations

```csharp
[ApiController]
[Route("api/orders")]
public sealed class OrdersController : ControllerBase
{
    [HttpPost]
    public ActionResult<Order> Create([FromBody] CreateOrderRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        // request is constrained by attributes and validated by the framework
        return CreatedAtAction(nameof(Get), new { id = 1 }, new Order(1, request.Quantity));
    }
}

public sealed record CreateOrderRequest(
    [property: Required, StringLength(64, MinimumLength = 1)] string CustomerId,
    [property: Range(1, 1000)] int Quantity);
```

`[ApiController]` enables automatic model-state validation. Attributes alone on a type that is
not validated by MVC are not a control.

### Explicit validation for minimal APIs

```csharp
app.MapPost("/api/orders", (CreateOrderRequest request) =>
{
    var errors = new Dictionary<string, string[]>();
    if (string.IsNullOrWhiteSpace(request.CustomerId) || request.CustomerId.Length > 64)
    {
        errors["customerId"] = ["CustomerId is required and must be at most 64 characters."];
    }
    if (request.Quantity is < 1 or > 1000)
    {
        errors["quantity"] = ["Quantity must be between 1 and 1000."];
    }
    return errors.Count > 0
        ? Results.ValidationProblem(errors)
        : Results.Created($"/api/orders/1", request);
});
```

Use an allowlist for enums and status values. Reject unknown or unexpected security-relevant
fields. Do not bind directly to entities that contain `IsAdmin`, `TenantId`, or `OwnerId`.

### Avoid

```csharp
// Disables automatic validation for every controller.
builder.Services.AddControllers(options =>
    options.SuppressModelStateInvalidFilter = true);

// Validation only on the client.
// <input required> is a usability feature, not a server-side control.
```

## Authentication

```csharp
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = false;
        options.LoginPath = "/account/login";
    });

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
```

Order matters: `UseAuthentication` must run before `UseAuthorization` and before endpoints.

JWT bearer baseline:

```csharp
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = true;
        options.Authority = "https://identity.example.com";
        options.Audience = "orders-api";
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromMinutes(1)
        };
    });
```

Do not disable issuer, audience, lifetime, or signature validation to make a token work. Do not
set `RequireHttpsMetadata = false` outside disposable local tests, and never in production code.

## Authorization

Function-level authorization:

```csharp
[Authorize]
[ApiController]
[Route("api/orders")]
public sealed class OrdersController : ControllerBase
{
    [HttpGet("{id:int}")]
    public async Task<ActionResult<Order>> Get(int id, CancellationToken ct)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId is null)
        {
            return Unauthorized();
        }

        var order = await _orders.FindForUserAsync(id, userId, ct);
        return order is null ? NotFound() : Ok(order);
    }

    [HttpDelete("{id:int}")]
    [Authorize(Policy = "CanDeleteOrders")]
    public async Task<IActionResult> Delete(int id, CancellationToken ct)
    {
        var deleted = await _orders.DeleteForUserAsync(id, User.GetUserId(), ct);
        return deleted ? NoContent() : NotFound();
    }
}
```

Object-level authorization must be in the query or service, not inferred from the route:

```csharp
public Task<Order?> FindForUserAsync(int id, string userId, CancellationToken ct) =>
    _db.Orders
       .Where(o => o.Id == id && o.CustomerId == userId)
       .Select(o => new Order(o.Id, o.CustomerId, o.Quantity))
       .FirstOrDefaultAsync(ct);
```

Returning `404` for both missing and unauthorized objects reduces enumeration. Do not trust a
role, tenant, or user ID from the request body. Derive identity from the validated principal.

Minimal API:

```csharp
var orders = app.MapGroup("/api/orders").RequireAuthorization();

orders.MapGet("/{id:int}", async (int id, ClaimsPrincipal user, OrderStore store, CancellationToken ct) =>
{
    var order = await store.FindForUserAsync(id, user.GetUserId(), ct);
    return order is null ? Results.NotFound() : Results.Ok(order);
});

// Explicitly public only when required and documented.
app.MapGet("/health", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
```

## Secrets management

```csharp
var apiKey = builder.Configuration["ExternalApi:ApiKey"];
if (string.IsNullOrWhiteSpace(apiKey))
{
    throw new InvalidOperationException("ExternalApi:ApiKey is not configured.");
}

builder.Services.AddSingleton(new ExternalApiClient(apiKey));
```

Production options:

- Azure Key Vault with managed identity.
- AWS Secrets Manager with an IAM role.
- HashiCorp Vault with workload identity.
- Kubernetes secrets only with encryption at rest and least-privilege RBAC.

Never:

```csharp
// Hardcoded values in source or appsettings.
var apiKey = "sk_live_51H8example";
var connectionString = "Server=db;User Id=app;Password=SuperSecret123;";

// Secrets in logs.
_logger.LogInformation("Calling API with key {Key}", apiKey);

// Secrets in query strings.
var url = $"https://api.example.com/orders?key={apiKey}";
```

Example configuration holds an empty placeholder:

```json
{
  "ExternalApi": {
    "BaseUrl": "https://api.example.com",
    "ApiKey": ""
  }
}
```

The application fails closed when the value is absent. That is intentional.

## SQL injection prevention

### EF Core

```csharp
// Safe: LINQ composition becomes parameterized SQL.
var orders = await _db.Orders
    .Where(o => o.CustomerId == customerId && o.Quantity >= minQuantity)
    .ToListAsync(ct);

// Safe: interpolated raw SQL is parameterized by EF Core.
var orders = await _db.Orders
    .FromSqlInterpolated($"SELECT * FROM Orders WHERE CustomerId = {customerId}")
    .ToListAsync(ct);
```

### ADO.NET

```csharp
await using var connection = new SqliteConnection(connectionString);
await connection.OpenAsync(ct);

await using var command = connection.CreateCommand();
command.CommandText = "SELECT Id, CustomerId, Quantity FROM Orders WHERE CustomerId = $customerId";
command.Parameters.AddWithValue("$customerId", customerId);

await using var reader = await command.ExecuteReaderAsync(ct);
```

### Dapper

```csharp
var orders = await connection.QueryAsync<Order>(
    "SELECT Id, CustomerId, Quantity FROM Orders WHERE CustomerId = @customerId",
    new { customerId });
```

### Avoid

```csharp
// SQL injection: interpolation and concatenation.
var sql = $"SELECT * FROM Orders WHERE CustomerId = '{customerId}'";
await using var command = new SqliteCommand(sql, connection);

var sql2 = "SELECT * FROM Orders WHERE CustomerId = '" + customerId + "'";
await _db.Orders.FromSqlRaw(sql2).ToListAsync();

// Dynamic identifiers cannot be parameterized; use a strict allowlist.
var sort = Request.Query["sort"];
var sql3 = $"SELECT * FROM Orders ORDER BY {sort}";
```

For identifiers, map user input to a fixed set:

```csharp
private static readonly IReadOnlyDictionary<string, string> SortColumns =
    new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["date"] = "CreatedAt",
        ["amount"] = "Quantity"
    };

if (!SortColumns.TryGetValue(sortKey, out var column))
{
    return BadRequest("Unsupported sort key.");
}
```

## OS command injection prevention

Prefer managed APIs. If a process is unavoidable:

```csharp
var startInfo = new ProcessStartInfo
{
    FileName = "dotnet",
    RedirectStandardOutput = true,
    RedirectStandardError = true,
    UseShellExecute = false,
    CreateNoWindow = true
};
startInfo.ArgumentList.Add("--version");

using var process = Process.Start(startInfo);
```

Never:

```csharp
// Shell injection: untrusted input becomes part of a shell command line.
Process.Start("cmd.exe", "/c ping " + host);

var info = new ProcessStartInfo("cmd.exe")
{
    Arguments = $"/c ping {host}",
    UseShellExecute = false
};
```

If an argument can be one of several operations, use an enum or allowlist and construct a fixed
argument vector. Do not attempt to escape shell metacharacters manually; remove the shell.

## Error handling and logging

- Return generic errors to clients; log details server-side with a correlation ID.
- Do not include stack traces, SQL, connection strings, or tokens in responses.
- Log authentication and authorization decisions, admin actions, and validation failures for
  sensitive operations, without logging credentials.
- Use structured logging and redact known secret keys.

```csharp
catch (Exception ex)
{
    _logger.LogError(ex, "Order creation failed for correlation {CorrelationId}", correlationId);
    return Problem(statusCode: 500, title: "An unexpected error occurred.");
}
```

## Tests

Add negative tests, not only happy-path tests:

```csharp
[Fact]
public async Task GetOrder_OtherUsersOrder_ReturnsNotFound()
{
    var client = factory.CreateAuthenticatedClient("user-a");
    var response = await client.GetAsync("/api/orders/42"); // owned by user-b
    Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
}

[Fact]
public async Task CreateOrder_InvalidQuantity_ReturnsBadRequest()
{
    var client = factory.CreateAuthenticatedClient("user-a");
    var response = await client.PostAsJsonAsync("/api/orders", new { customerId = "user-a", quantity = 0 });
    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
}
```

Keep test credentials fake and obviously non-production. A fake secret pattern can still trip a
secret scanner; use placeholders or generated test-only values and never a real credential.

## Secure defaults checklist

- HTTPS redirection and HSTS outside local development.
- `UseAuthentication` and `UseAuthorization` present and ordered.
- Fallback policy requires authentication unless the application is intentionally public.
- Cookies `HttpOnly`, `Secure`, `SameSite`.
- Antiforgery for cookie-authenticated state-changing browser forms.
- CORS restricted to known origins, never `AllowAnyOrigin` with credentials.
- Rate limiting on authentication and expensive endpoints.
- Request body size limits and timeouts.
- No detailed errors in production.
- Dependencies pinned and monitored.
- No secrets in source, configuration, tests, logs, or artifacts.
