FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

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
