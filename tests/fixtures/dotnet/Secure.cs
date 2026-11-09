// Secure counterpart of Insecure.cs: must produce no findings.
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text.Json;

public class Secure
{
    public void Query(string name, SqlConnection conn)
    {
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = @name", conn);
        cmd.Parameters.AddWithValue("@name", name);
        cmd.ExecuteReader();
    }

    public T Load<T>(string json)
    {
        return JsonSerializer.Deserialize<T>(json);
    }

    public void Crypto()
    {
        var aes = new AesGcm(new byte[32]);
        var sha = SHA256.Create();
    }
}
