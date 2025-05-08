namespace ClientBff.Client;

public static class CommonServicesRegistration
{
    public static IServiceCollection AddCommonServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpClient("ServerAPI", client =>
            client.BaseAddress = new Uri("https://localhost:9090"));
        services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>()
            .CreateClient("ServerAPI"));
        services.AddSingleton(sp =>
        {
            var httpClient = new HttpClient()
            {
                BaseAddress = new Uri("https://localhost:9090")
            };
            return httpClient;
        });
        return services;
    }
}
