# Vulnerable .NET Lab

An intentionally vulnerable ASP.NET Core API for SAST, SCA, secret scanning, and local exploitation practice. Requires the .NET 10 SDK and NuGet access. Command injection uses `/bin/sh` (Linux/macOS).

Run on a disposable local environment; these endpoints intentionally allow command execution, local file reads, and arbitrary outbound requests. The default listener is `http://127.0.0.1:5080`. All credentials and records are synthetic.

```sh
dotnet restore scan-target/App/App.csproj
dotnet run --project scan-target/App
```

Open http://127.0.0.1:5080. Use `requests.http` with an HTTP client, or run the local smoke checks while the server is running:

```sh
python3 scripts/smoke.py
dotnet list scan-target/App/App.csproj package --vulnerable --include-transitive
```

See [the findings guide](docs/FINDINGS.md) for intended findings and dependency advisories. There are two deliberately vulnerable direct dependencies, which can produce three or more advisory findings depending on the scanner database and transitive packages. Restore generates a packages.lock.json file for repeatable scans; retain it after the first successful restore. Do not automatically update dependencies if you want to retain the exercise.

`App_Data/lab.db` is seeded on first startup. Delete `scan-target/App/App_Data` with the app stopped to reset the lab. Configuration credentials are scanning fixtures; they are not used to connect to external services. The login endpoint returns a user record and does not establish a session.

## Scan boundary

Point scanners at **`scan-target/` only**, or copy that directory to a separate checkout or upload archive. It contains the application, configuration, secret fixtures, and dependency lockfile. Run from the repository root with `dotnet run --project scan-target/App`.

The answer key (`FLAWS.md`, `docs/FINDINGS.md`), this README, sample requests, and smoke checks remain outside the scan target. Directory organization does not restrict an agent's filesystem access: for a blind LLM scan, provide only a copy of `scan-target/`, without the parent repository or earlier conversation context.
