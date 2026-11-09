// Intentionally vulnerable test data for slsec-sast. Do not use.
using System.Data.SqlClient;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Xml;

public class Insecure
{
    public void Query(string name, SqlConnection conn)
    {
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
        cmd.ExecuteReader();
    }

    public object Load(Stream s)
    {
        return new BinaryFormatter().Deserialize(s);
    }

    public void Crypto()
    {
        Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        DES des = DES.Create();
    }

    public void Xml(string xml)
    {
        XmlTextReader reader = new XmlTextReader(xml);
        reader.Read();
    }

    public string Path(string file)
    {
        return System.IO.Path.Combine("/var/data", file);
    }
}
