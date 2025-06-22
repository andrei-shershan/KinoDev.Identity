## KinoDev.Identity

### Local Setup

#### NuGet Configuration
```
dotnet nuget add source "https://nuget.pkg.github.com/andrei-shershan/index.json" --name GitHub --username YOUR_GITHUB_USERNAME --password YOUR_PERSONAL_ACCESS_TOKEN --store-password-in-clear-text

dotnet restore

dotnet add package KinoDev.Shared
```

### Database Options

#### In-Memory Database
The application is configured to use an in-memory database by default for development purposes. This is controlled by the `InMemoryDatabase` section in the `appsettings.json`:

```json
"InMemoryDatabase": {
  "Enabled": true,
  "DatabaseName": "KinoDevIdentity" 
}
```

The in-memory database is particularly useful for:
- Local development without requiring a MySQL instance
- Testing scenarios
- CI/CD pipelines

#### MySQL Database
To use MySQL instead of the in-memory database:

1. Set `"Enabled": false` in the `InMemoryDatabase` section of your `appsettings.json`
2. Ensure your MySQL connection string in `ConnectionStrings:Identity` is properly configured

Note that when using MySQL, you'll need to run migrations to create the database schema.
