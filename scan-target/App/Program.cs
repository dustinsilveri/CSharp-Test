using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using System.Linq.Dynamic.Core;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:5080");
var app = builder.Build();
var dataDirectory = Path.Combine(app.Environment.ContentRootPath, "App_Data");
Directory.CreateDirectory(dataDirectory);
Directory.CreateDirectory(Path.Combine(dataDirectory, "files"));
File.WriteAllText(Path.Combine(dataDirectory, "files", "welcome.txt"), "Welcome to the lab.");
var connectionString = new SqliteConnectionStringBuilder { DataSource = Path.Combine(dataDirectory, "lab.db") }.ToString();
using (var db = new SqliteConnection(connectionString))
{
    db.Open();
    using var seed = db.CreateCommand();
    seed.CommandText = """
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        INSERT OR IGNORE INTO users VALUES (1, 'alice', 'alice-lab-password', 'user'), (2, 'admin', 'admin-lab-password', 'admin');
        CREATE TABLE IF NOT EXISTS invoices (id INTEGER PRIMARY KEY, owner TEXT, amount INTEGER, bankAccount TEXT);
        INSERT OR IGNORE INTO invoices VALUES (1, 'alice', 125, 'DEMO-ACCOUNT-001'), (2, 'bob', 900, 'DEMO-ACCOUNT-002');
        """;
    seed.ExecuteNonQuery();
}

app.MapGet("/", () => Results.Content("""
    <html><body><h1>Service Portal</h1><p>Local service API.</p>
    <p>Service is running.</p></body></html>
    """, "text/html"));

app.MapPost("/api/login", (LoginRequest request) =>
{
    using var db = new SqliteConnection(connectionString);
    db.Open();
    using var command = db.CreateCommand();
    command.CommandText = $"SELECT id, username, role FROM users WHERE username = '{request.Username}' AND password = '{request.Password}'";
    using var reader = command.ExecuteReader();
    return reader.Read()
        ? Results.Ok(new { id = reader.GetInt64(0), username = reader.GetString(1), role = reader.GetString(2) })
        : Results.Unauthorized();
});

app.MapGet("/api/diagnostics", async (string host) =>
{
    var start = new ProcessStartInfo("/bin/sh") { RedirectStandardOutput = true, RedirectStandardError = true };
    start.ArgumentList.Add("-c");
    start.ArgumentList.Add("echo Looking up " + host);
    using var process = Process.Start(start)!;
    var stdout = process.StandardOutput.ReadToEndAsync();
    var stderr = process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();
    return Results.Ok(new { output = await stdout, error = await stderr });
});

app.MapPost("/api/import", async (HttpRequest request) =>
{
    var body = await new StreamReader(request.Body).ReadToEndAsync();
    var imported = JsonConvert.DeserializeObject(body, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
    return Results.Ok(new { type = imported?.GetType().FullName, value = imported?.ToString() });
});

app.MapGet("/api/users/filter", (string expression) =>
{
    var users = new[] { new LabUser("alice", "user"), new LabUser("admin", "admin") }.AsQueryable();
    return Results.Ok(users.Where(expression).ToArray());
});

app.MapPost("/api/crypto/encrypt", (TextRequest request) =>
{
    using var aes = Aes.Create();
    aes.Key = Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");
    aes.Mode = CipherMode.ECB;
    aes.Padding = PaddingMode.PKCS7;
    using var encryptor = aes.CreateEncryptor();
    var bytes = Encoding.UTF8.GetBytes(request.Text);
    return Results.Ok(new { ciphertext = Convert.ToBase64String(encryptor.TransformFinalBlock(bytes, 0, bytes.Length)) });
});
app.MapPost("/api/crypto/hash", (TextRequest request) =>
    Results.Ok(new { hash = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(request.Text))) }));
app.MapGet("/api/reset-token", () => Results.Ok(new { token = new Random().Next(100000, 999999).ToString() }));

app.MapGet("/api/files", (string name) => Results.Text(File.ReadAllText(Path.Combine(dataDirectory, "files", name))));
app.MapGet("/hello", (string name) => Results.Content("<html><body>Hello " + name + "</body></html>", "text/html"));
app.MapGet("/api/fetch", async (string url) =>
{
    using var client = new HttpClient();
    return Results.Text(await client.GetStringAsync(url));
});
app.MapGet("/api/invoices/{id:int}", (int id) =>
{
    using var db = new SqliteConnection(connectionString);
    db.Open();
    using var command = db.CreateCommand();
    command.CommandText = "SELECT owner, amount, bankAccount FROM invoices WHERE id = $id";
    command.Parameters.AddWithValue("$id", id);
    using var reader = command.ExecuteReader();
    return reader.Read() ? Results.Ok(new { owner = reader.GetString(0), amount = reader.GetInt64(1), bankAccount = reader.GetString(2) }) : Results.NotFound();
});
app.MapGet("/redirect", (string url) => Results.Redirect(url));
app.MapPost("/api/xml", async (HttpRequest request) =>
{
    var xml = await new StreamReader(request.Body).ReadToEndAsync();
    var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
    using var reader = XmlReader.Create(new StringReader(xml), settings);
    var document = new XmlDocument { XmlResolver = new XmlUrlResolver() };
    document.Load(reader);
    return Results.Text(document.InnerText);
});
app.Run();

public record LoginRequest(string Username, string Password);
public record TextRequest(string Text);
public record LabUser(string Username, string Role);
