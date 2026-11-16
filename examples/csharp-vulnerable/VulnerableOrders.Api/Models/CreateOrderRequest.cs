namespace VulnerableOrders.Api.Models;

public sealed class CreateOrderRequest
{
    public string CustomerId { get; set; } = string.Empty;
    public decimal Amount { get; set; }
    public string Description { get; set; } = string.Empty;
}
