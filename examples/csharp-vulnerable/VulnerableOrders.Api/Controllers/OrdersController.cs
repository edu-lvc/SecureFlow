using Microsoft.AspNetCore.Mvc;
using VulnerableOrders.Api.Models;
using VulnerableOrders.Api.Services;

namespace VulnerableOrders.Api.Controllers;

// INTENTIONALLY INSECURE: no [Authorize] and no global fallback policy.
[ApiController]
[Route("api/orders")]
public sealed class OrdersController : ControllerBase
{
    private readonly OrderRepository _repository;
    private readonly DiagnosticsService _diagnostics;

    public OrdersController(OrderRepository repository, DiagnosticsService diagnostics)
    {
        _repository = repository;
        _diagnostics = diagnostics;
    }

    [HttpGet("{id}")]
    public ActionResult<Order> GetById(string id)
    {
        var order = _repository.GetById(id);
        return order is null ? NotFound() : Ok(order);
    }

    [HttpPost]
    public ActionResult<Order> Create([FromBody] CreateOrderRequest request)
    {
        var created = _repository.Create(request.CustomerId, request.Amount, request.Description);
        return Ok(created);
    }

    [HttpPost("diagnostics")]
    public ActionResult<string> RunDiagnostics([FromQuery] string host)
    {
        return Ok(_diagnostics.Ping(host));
    }
}
