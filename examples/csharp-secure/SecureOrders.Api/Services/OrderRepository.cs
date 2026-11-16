using Microsoft.Data.Sqlite;
using SecureOrders.Api.Models;

namespace SecureOrders.Api.Services;

public sealed class OrderRepository
{
    private readonly string _connectionString;

    public OrderRepository(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("Orders")
            ?? "Data Source=orders.db";
        Initialize();
    }

    private void Initialize()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "CREATE TABLE IF NOT EXISTS Orders (Id INTEGER PRIMARY KEY AUTOINCREMENT, CustomerId TEXT NOT NULL, Amount TEXT NOT NULL, Description TEXT NOT NULL)";
        command.ExecuteNonQuery();
    }

    public Order? GetById(long id)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var command = new SqliteCommand(
            "SELECT Id, CustomerId, Amount, Description FROM Orders WHERE Id = $id",
            connection);
        command.Parameters.AddWithValue("$id", id);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }
        return new Order
        {
            Id = reader.GetInt64(0),
            CustomerId = reader.GetString(1),
            Amount = decimal.Parse(reader.GetString(2), System.Globalization.CultureInfo.InvariantCulture),
            Description = reader.GetString(3),
        };
    }

    public Order Create(string customerId, decimal amount, string description)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var insert = new SqliteCommand(
            "INSERT INTO Orders (CustomerId, Amount, Description) VALUES ($customerId, $amount, $description)",
            connection);
        insert.Parameters.AddWithValue("$customerId", customerId);
        insert.Parameters.AddWithValue("$amount", amount.ToString(System.Globalization.CultureInfo.InvariantCulture));
        insert.Parameters.AddWithValue("$description", description);
        insert.ExecuteNonQuery();

        using var idCommand = new SqliteCommand("SELECT last_insert_rowid()", connection);
        var id = (long)(idCommand.ExecuteScalar() ?? 0L);
        return new Order
        {
            Id = id,
            CustomerId = customerId,
            Amount = amount,
            Description = description,
        };
    }
}
