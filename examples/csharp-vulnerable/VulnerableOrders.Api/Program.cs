using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using VulnerableOrders.Api.Services;

var builder = WebApplication.CreateBuilder(args);

// INTENTIONALLY INSECURE: this example exists only for negative gate tests.
builder.Services.AddControllers();
builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.SuppressModelStateInvalidFilter = true;
});
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = false;
        options.Cookie.SecurePolicy = CookieSecurePolicy.None;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.LoginPath = "/login";
    });
builder.Services.AddAuthorization();
builder.Services.AddSingleton<OrderRepository>();
builder.Services.AddSingleton<DiagnosticsService>();

var app = builder.Build();

// INTENTIONALLY INSECURE: UseAuthentication is missing.
app.UseAuthorization();
app.MapControllers();

app.Run();

public partial class Program
{
}
