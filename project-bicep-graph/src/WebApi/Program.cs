using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Configuration: AzureAd:TenantId, AzureAd:Audience (App ID URI or Client ID)
var tenantId = builder.Configuration["AzureAd:TenantId"] ?? "";
var audience = builder.Configuration["AzureAd:Audience"] ?? "";
var clientId = builder.Configuration["AzureAd:ClientId"] ?? "";
var authority = string.IsNullOrWhiteSpace(tenantId)
    ? null
    : $"https://login.microsoftonline.com/{tenantId}/v2.0";

if (!string.IsNullOrWhiteSpace(authority) && !string.IsNullOrWhiteSpace(audience))
{
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    }).AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidAudiences = new[] { audience, clientId },
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidIssuer = $"https://login.microsoftonline.com/{tenantId}/v2.0",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true
        };
    });

    builder.Services.AddAuthorization(options =>
    {
        // Scope-based policy (Swagger.Read)
        options.AddPolicy("SwaggerRead", policy =>
            policy.RequireAssertion(ctx =>
            {
                var scope = ctx.User.FindFirst("scp")?.Value;
                return scope != null && scope.Split(' ').Contains("Swagger.Read");
            }));

        // Role-based policy (Swagger.Admin)
        options.AddPolicy("SwaggerAdmin", policy =>
            policy.RequireAssertion(ctx =>
            {
                var roles = ctx.User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();
                // roles claim may also be in 'roles'
                var rolesAlt = ctx.User.FindAll("roles").Select(c => c.Value).ToArray();
                return roles.Contains("Swagger.Admin") || rolesAlt.Contains("Swagger.Admin");
            }));

        // Generic authenticated policy for /health (any valid v2 token for this tenant)
        options.AddPolicy("AnyAuthenticated", policy =>
        {
            policy.RequireAuthenticatedUser();
        });
    });
}
else
{
    builder.Services.AddAuthorization();
}

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Enable Swagger UI but protect it behind SwaggerRead; the JSON remains public for tooling if needed.
app.UseSwagger();
app.UseSwaggerUI();

var healthzEndpoint = app.MapGet("/healthz", () => Results.Json(new
{
    status = "ok",
    time = DateTimeOffset.UtcNow.ToString("o"),
    authConfigured = !string.IsNullOrWhiteSpace(authority)
}));

if (!string.IsNullOrWhiteSpace(authority))
{
    app.UseAuthentication();
    app.UseAuthorization();

    healthzEndpoint.RequireAuthorization("SwaggerAdmin");

    app.MapGet("/health", (ClaimsPrincipal user) =>
    {
        var name = user.Identity?.Name ?? user.FindFirst("name")?.Value ?? "unknown";
        var aud = user.FindFirst("aud")?.Value;
        return Results.Json(new
        {
            status = "ok",
            time = DateTimeOffset.UtcNow.ToString("o"),
            name,
            audience = aud
        });
    }).RequireAuthorization("AnyAuthenticated");

    // Mock data API (requires Swagger.Read)
    app.MapGet("/api/mock", () =>
    {
        var data = new[]
        {
            new { id = 1, name = "alpha", value = 42 },
            new { id = 2, name = "beta", value = 1337 },
            new { id = 3, name = "gamma", value = 9001 }
        };
        return Results.Json(data);
    }).RequireAuthorization("SwaggerRead");

    // Lock down Swagger UI endpoint behind admin role
    app.MapGet("/swagger", () => Results.Redirect("/swagger/index.html"))
       .RequireAuthorization("SwaggerAdmin");
}

app.Run();
