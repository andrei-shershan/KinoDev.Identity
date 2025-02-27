FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

ARG GITHUB_READ_PACKAGE_TOKEN
ARG GITHUB_USER_NAME

# Write a NuGet.config file with credentials in clear text using the build argument.
RUN echo "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
<configuration>\n\
  <packageSources>\n\
    <add key=\"GitHub\" value=\"https://nuget.pkg.github.com/andrei-shershan/index.json\" />\n\
    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n\
  </packageSources>\n\
  <packageSourceCredentials>\n\
    <GitHub>\n\
      <add key=\"Username\" value=\"${GITHUB_USER_NAME}\" />\n\
      <add key=\"ClearTextPassword\" value=\"$GITHUB_READ_PACKAGE_TOKEN\" />\n\
    </GitHub>\n\
  </packageSourceCredentials>\n\
</configuration>" > /root/.nuget/NuGet/NuGet.Config

# Copy solution and projects
COPY ["KinoDev.Identity.sln", "./"]
COPY ["KinoDev.Identity.csproj", "./"]

RUN dotnet restore "KinoDev.Identity.csproj"

# Copy full source and build
COPY . .
WORKDIR "/src"
RUN dotnet build "KinoDev.Identity.csproj" -c Release -o /app/build

# Add a stage for running tests
# FROM build AS testrunner
# WORKDIR /src/tests/FoodExpress.Api.UnitTests
# RUN dotnet test "FoodExpress.Api.UnitTests.csproj" --logger:trx

FROM build AS publish
RUN dotnet publish "KinoDev.Identity.csproj" -c Release -o /app/publish /p:UseAppHost=false


FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "KinoDev.Identity.dll"]
