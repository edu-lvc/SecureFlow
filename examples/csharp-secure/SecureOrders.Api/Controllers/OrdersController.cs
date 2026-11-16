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

    public OrdersController(OrderRepository repository)
    {
        _repository = repository;
    }

    [HttpGet("{id:long}")]
    public ActionResult<Order> GetById(long id)
    {
        var order = _repository.GetById(id);
        return order is null ? NotFound() : Ok(order);
    }

    [HttpPost]
    public ActionResult<Order> Create([FromBody] CreateOrderRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        var created = _repository.Create(request.CustomerId, request.Amount, request.Description);
        return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
    }
}
