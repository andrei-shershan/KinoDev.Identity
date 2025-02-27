## Local Setup
# Add nuget source
dotnet nuget add source "https://nuget.pkg.github.com/andrei-shershan/index.json" --name GitHub --username YOUR_GITHUB_USERNAME --password YOUR_PERSONAL_ACCESS_TOKEN --store-password-in-clear-text

dotnet restore

dotnet add package KinoDev.Shared


