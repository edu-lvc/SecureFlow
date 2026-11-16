namespace SecureOrders.Api.Models;

public sealed class Order
{
    public long Id { get; init; }
    public string CustomerId { get; init; } = string.Empty;
    public decimal Amount { get; init; }
    public string Description { get; init; } = string.Empty;
}
