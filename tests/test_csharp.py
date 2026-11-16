"""Tests for the intentionally small C# and ASP.NET Core parser."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.support import write_project

from secureflow_gate.csharp import mask_csharp, parse_csharp
from secureflow_gate.scanner import scan_tree


def parsed(files):
    with tempfile.TemporaryDirectory(prefix="secureflow-csharp-") as directory:
        root = Path(directory)
        write_project(root, files)
        scanned, _, _ = scan_tree(str(root))
        return parse_csharp(scanned)


CONTROLLER = """using Microsoft.AspNetCore.Authorization;
namespace Demo;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class WidgetsController : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok();

    [HttpPost]
    public IActionResult Create() => Ok();

    [AllowAnonymous]
    [HttpPost("public")]
    public IActionResult Public() => Ok();

    [HttpPost("open")]
    public IActionResult Open() => Ok();
}
"""


class CSharpParserTests(unittest.TestCase):
    def test_masking_removes_comments_and_string_contents(self) -> None:
        source = 'var a = "Process.Start(evil)"; // [Authorize]\n/* [HttpPost] */ var b = 1;'
        masked = mask_csharp(source)
        self.assertNotIn("Process.Start", masked)
        self.assertNotIn("[Authorize]", masked)
        self.assertNotIn("[HttpPost]", masked)
        self.assertEqual(len(source), len(masked))
        self.assertIn("var a", masked)

    def test_controller_attributes_and_allow_anonymous(self) -> None:
        model = parsed({"WidgetsController.cs": CONTROLLER})
        by_label = {endpoint.label: endpoint for endpoint in model.endpoints}
        self.assertIn("WidgetsController.Get", by_label)
        self.assertTrue(by_label["WidgetsController.Get"].protected)
        self.assertFalse(by_label["WidgetsController.Get"].mutating)
        self.assertTrue(by_label["WidgetsController.Create"].mutating)
        self.assertTrue(by_label["WidgetsController.Create"].protected)
        self.assertTrue(by_label["WidgetsController.Public"].anonymous)
        self.assertFalse(by_label["WidgetsController.Public"].protected)
        self.assertTrue(by_label["WidgetsController.Open"].protected)
        self.assertEqual(3, len(model.mutating_endpoints))
        self.assertEqual(["WidgetsController.Public"], [e.label for e in model.anonymous_endpoints])

    def test_comment_cannot_protect_an_endpoint(self) -> None:
        source = """using Microsoft.AspNetCore.Mvc;
// [Authorize]
public class OpenController : ControllerBase
{
    [HttpPost]
    public IActionResult Create() => Ok();
}
"""
        model = parsed({"OpenController.cs": source})
        self.assertFalse(model.endpoints[0].protected)

    def test_class_level_fallback_policy_protects_endpoints(self) -> None:
        source = """using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});
public class OpenController : ControllerBase
{
    [HttpPost]
    public IActionResult Create() => Ok();
}
"""
        model = parsed({"Program.cs": source, "OpenController.cs": source})
        self.assertTrue(model.fallback)
        self.assertTrue(all(endpoint.protected for endpoint in model.mutating_endpoints))

    def test_minimal_api_mutation_is_detected(self) -> None:
        source = """var app = builder.Build();
app.MapPost("/widgets", (Widget request) => Results.Ok(request));
app.MapGet("/widgets", () => Results.Ok());
app.MapDelete("/widgets/{id}", (int id) => Results.NoContent())
   .RequireAuthorization();
"""
        model = parsed({"Program.cs": source})
        labels = {endpoint.label: endpoint for endpoint in model.endpoints}
        self.assertIn("MapPost/widgets", labels)
        self.assertFalse(labels["MapPost/widgets"].protected)
        self.assertIn("MapDelete/widgets/{id}", labels)
        self.assertTrue(labels["MapDelete/widgets/{id}"].protected)

    def test_custom_authentication_scheme_is_recognized(self) -> None:
        model = parsed(
            {
                "Program.cs": """using Microsoft.AspNetCore.Authentication;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication().AddScheme<MyOptions, MyHandler>("Custom", null);
var app = builder.Build();
"""
            }
        )
        self.assertTrue(model.has_auth_config)
        self.assertTrue(model.has_auth_scheme)

    def test_fallback_and_auth_configuration_are_detected(self) -> None:
        source = """builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie();
builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
"""
        model = parsed({"Program.cs": source})
        self.assertTrue(model.has_auth_config)
        self.assertTrue(model.has_cookie_auth)
        self.assertTrue(model.use_authentication)

    def test_insecure_cookie_flags_are_detected(self) -> None:
        source = """builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = false;
        options.Cookie.SecurePolicy = CookieSecurePolicy.None;
    });
"""
        model = parsed({"Program.cs": source})
        self.assertTrue(model.httponly_false)
        self.assertTrue(model.secure_none)

    def test_method_with_default_parameter_is_detected(self) -> None:
        source = """public class ItemsController : ControllerBase
{
    [HttpPost]
    public IActionResult Create(int id = 1) => Ok();
}
"""
        model = parsed({"ItemsController.cs": source})
        self.assertEqual(["ItemsController.Create"], [endpoint.label for endpoint in model.endpoints])
        self.assertTrue(model.endpoints[0].mutating)

    def test_minimal_api_block_lambda_keeps_authorization(self) -> None:
        source = """app.MapPost("/items", (HttpRequest request) =>
{
    var value = 1;
    return Results.Ok(value);
}).RequireAuthorization();
"""
        model = parsed({"Program.cs": source})
        self.assertEqual(1, len(model.endpoints))
        self.assertTrue(model.endpoints[0].protected)

    def test_unregistered_authorize_filter_is_not_a_fallback(self) -> None:
        source = """var filter = new AuthorizeFilter();
app.MapPost("/items", () => Results.Ok());
"""
        model = parsed({"Program.cs": source})
        self.assertIsNone(model.fallback)
        self.assertFalse(model.endpoints[0].protected)


if __name__ == "__main__":
    unittest.main()
