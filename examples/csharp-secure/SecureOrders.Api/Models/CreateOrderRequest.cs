using System.ComponentModel.DataAnnotations;

namespace SecureOrders.Api.Models;

public sealed class CreateOrderRequest
{
    [Required]
    [StringLength(64, MinimumLength = 1)]
    public string CustomerId { get; set; } = string.Empty;

    [Range(0.01, 1000000)]
    public decimal Amount { get; set; }

    [Required]
    [StringLength(200, MinimumLength = 1)]
    public string Description { get; set; } = string.Empty;
}
