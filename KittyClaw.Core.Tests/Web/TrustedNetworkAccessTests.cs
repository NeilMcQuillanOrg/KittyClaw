using System.Net;
using KittyClaw.Core.Services;
using KittyClaw.Core.Tests.Helpers;
using KittyClaw.Web.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace KittyClaw.Core.Tests.Web;

public sealed class TrustedNetworkAccessTests
{
    [Fact]
    public async Task Middleware_pipeline_reads_trusted_network_from_host_configuration()
    {
        using TempDir directory = new();
        using IHost host = new HostBuilder().ConfigureWebHost(web => web.UseTestServer()
            .UseSetting("NetworkAccess:TrustedNetwork", "true")
            .ConfigureServices(services =>
            {
                services.AddLogging();
                services.AddAntiforgery();
                services.AddDataProtection().UseEphemeralDataProtectionProvider();
                services.AddSingleton(new NetworkAccessService(
                    directory.Path, new EphemeralDataProtectionProvider(), 5233));
                services.AddSingleton(new LocalizationService(new AppSettingsService(
                    directory.Path, System.Globalization.CultureInfo.GetCultureInfo("en"))));
            })
            .Configure(app =>
            {
                app.Use(async (context, next) =>
                {
                    context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.42");
                    await next(context);
                });
                app.UseMiddleware<NetworkAccessMiddleware>();
                app.Run(context => context.Response.WriteAsync("allowed"));
            })).Start();
        using HttpClient client = host.GetTestServer().CreateClient();

        HttpResponseMessage response = await client.GetAsync("http://pc.test/api/projects");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("allowed", await response.Content.ReadAsStringAsync());
    }
    [Theory]
    [InlineData("http", "/", "GET")]
    [InlineData("http", "/api/projects", "GET")]
    [InlineData("http", "/api/projects", "POST")]
    [InlineData("http", "/mcp", "POST")]
    [InlineData("http", "/_blazor/negotiate", "POST")]
    [InlineData("http", "/_blazor", "GET")]
    [InlineData("http", "/uploads/private.png", "GET")]
    [InlineData("https", "/", "GET")]
    public async Task Explicit_opt_in_allows_access_without_enrollment_or_cookies(
        string scheme, string path, string method)
    {
        using TempDir directory = new();
        NetworkAccessService access = new(directory.Path, new EphemeralDataProtectionProvider(), 5233);
        DefaultHttpContext context = CreateContext(scheme, path, method);
        context.Request.Headers.Origin = $"{scheme}://pc.test";
        context.Request.Headers["Sec-Fetch-Site"] = "same-origin";
        bool reachedEndpoint = false;
        NetworkAccessMiddleware middleware = new(_ =>
        {
            reachedEndpoint = true;
            return Task.CompletedTask;
        }, Configuration("true"));

        await middleware.InvokeAsync(context, access, null!, null!);

        Assert.False(access.Enabled);
        Assert.Empty(context.Request.Cookies);
        Assert.True(reachedEndpoint);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Theory]
    [InlineData(null, false, "/", null, null)]
    [InlineData("false", false, "/", null, null)]
    [InlineData("true", false, "/network-setup", null, null)]
    [InlineData("true", false, "/network-setup/anything", null, null)]
    [InlineData("true", false, "/api/projects", "https://evil.test", null)]
    [InlineData("true", false, "/_blazor", "https://evil.test", null)]
    [InlineData("true", false, "/api/projects", "null", null)]
    [InlineData("true", false, "/api/projects", null, "cross-site")]
    [InlineData("true", false, "/api/projects", null, "same-site")]
    [InlineData("true", true, "/", null, null)]
    public async Task Opt_in_preserves_default_origin_setup_and_tunnel_boundaries(
        string? setting, bool tunnel, string path, string? origin, string? site)
    {
        using TempDir directory = new();
        NetworkAccessService access = new(directory.Path, new EphemeralDataProtectionProvider(), 5233);
        DefaultHttpContext context = CreateContext(tunnel ? "https" : "http", path, "POST");
        if (origin is not null) context.Request.Headers.Origin = origin;
        if (site is not null) context.Request.Headers["Sec-Fetch-Site"] = site;
        if (tunnel) context.Features.Set(new RemoteTunnelRequest());
        bool reachedEndpoint = false;
        NetworkAccessMiddleware middleware = new(_ =>
        {
            reachedEndpoint = true;
            return Task.CompletedTask;
        }, Configuration(setting));

        await middleware.InvokeAsync(context, access, null!, null!);

        Assert.False(reachedEndpoint);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public async Task Trusted_network_does_not_bypass_enrolled_tunnel_session_gate()
    {
        using TempDir directory = new();
        NetworkAccessService access = new(directory.Path, new EphemeralDataProtectionProvider(), 5233);
        string enrollment = access.CreateEnrollment();
        string secret = access.EnrollmentSecret(enrollment);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        string bits = string.Concat(secret.Select(character =>
            Convert.ToString(alphabet.IndexOf(character), 2).PadLeft(5, '0')));
        byte[] key = Enumerable.Range(0, bits.Length / 8)
            .Select(index => Convert.ToByte(bits.Substring(index * 8, 8), 2)).ToArray();
        Assert.True(access.Enable(enrollment,
            NetworkAccessService.Totp(key, DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30)));
        DefaultHttpContext context = CreateContext("https", "/_blazor", "GET");
        context.Features.Set(new RemoteTunnelRequest());
        NetworkAccessMiddleware middleware = new(_ =>
            throw new InvalidOperationException("Tunnel must require a session."), Configuration("true"));

        await middleware.InvokeAsync(context, access, null!, null!);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    private static IConfiguration Configuration(string? setting) =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["NetworkAccess:TrustedNetwork"] = setting
        }).Build();

    private static DefaultHttpContext CreateContext(string scheme, string path, string method)
    {
        DefaultHttpContext context = new();
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.42");
        context.Request.Scheme = scheme;
        context.Request.Host = new HostString("pc.test");
        context.Request.Path = path;
        context.Request.Method = method;
        return context;
    }
}