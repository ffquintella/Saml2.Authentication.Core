# SAML authentication 

This package allows you to authenticate using SAML in your ASP.NET Core application.

## Installation

You can install the package via NuGet:

```
dotnet add package UOX.Saml2.Authentication
```

## Usage

### Startup

```csharp
// This method gets called by the runtime. Use this method to add services to the container.

public void ConfigureServices(IServiceCollection services)
{
    services.AddScoped<IUserClaimsPrincipalFactory<TUser>, DemoWebAppClaimsPrincipalFactory>();		
    services.Configure<Saml2Configuration>(Configuration.GetSection("Saml2"));

    services.AddSaml();

    // Single idp
    services.AddAuthentication()
        .AddCookie("saml2.cookies", options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        })
        .AddSaml("saml2", "saml2", options =>
        {
            options.SignInScheme = "saml2.cookies";
            options.IdentityProviderName = "stubidp.sustainsys";
        });
        
    // Multiple idps
    services.AddAuthentication()
        .AddCookie("saml2.idp1.cookies", options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        })
        .AddCookie("saml2.idp2.cookies", options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        })
        .AddSaml("saml2.idp1", "saml2.idp1", options =>
        {
            options.SignInScheme = "saml2.idp1.cookies";
            options.IdentityProviderName = "idp1";
        })
        .AddSaml("saml2.idp2", "saml2.idp2", options =>
         {
             options.SignInScheme = "saml2.idp2.cookies";
             options.IdentityProviderName = "idp2";
         });

    services.AddMvc();
}
```