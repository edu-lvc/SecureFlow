using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureOrders.Api.Models;
using SecureOrders.Api.Services;

namespace SecureOrders.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/orders")]
public sealed class OrdersController : ControllerBase
{
    private readonly OrderRepository _repository;
    private readonly ILogger<OrdersController> _logger;

    public OrdersController(OrderRepository repository, ILogger<OrdersController> logger)
    {
        _repository = repository;
        _logger = logger;
    }

    [HttpGet("{id:long}")]
    public ActionResult<Order> GetById(long id)
    {
        _logger.LogInformation("Authenticated user accessed order {OrderId}", id);
        var order = _repository.GetById(id);
        return order is null ? NotFound() : Ok(order);
    }

    [HttpPost]
    public ActionResult<Order> Create([FromBody] CreateOrderRequest request)
    {
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Order create request failed validation");
            return ValidationProblem(ModelState);
        }

        var created = _repository.Create(request.CustomerId, request.Amount, request.Description);
        _logger.LogInformation("Authenticated user created order {OrderId}", created.Id);
        return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
    }
}
