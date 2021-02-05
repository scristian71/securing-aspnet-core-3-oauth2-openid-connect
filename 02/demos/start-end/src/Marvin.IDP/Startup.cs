// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using IdentityServerHost.Quickstart.UI;
using System.Reflection;
using Microsoft.EntityFrameworkCore;
using IdentityServer4.EntityFramework.DbContexts;
using System.Linq;
using IdentityServer4.EntityFramework.Mappers;
using Marvin.IDP.DbContexts;
using Marvin.IDP.Services;
using Microsoft.AspNetCore.Identity;
using IdentityServer4;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authorization;

namespace Marvin.IDP
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var marvinIDPDataDBConnectionString = 
                "Host=127.0.0.1; Port=5433; Username=oauth_idt; Password=idt123; Database=oauth_idt; pooling=true";

            // uncomment, if you want to add an MVC-based UI
            services.AddControllersWithViews();

            services.AddDbContext<IdentityDbContext>(options =>
            {
                options.UseNpgsql(marvinIDPDataDBConnectionString);
            });

            services.AddScoped<IPasswordHasher<Entities.User>, PasswordHasher<Entities.User>>();
            services.AddScoped<ILocalUserService, LocalUserService>();

            var builder = services.AddIdentityServer(options =>
            {
                // see https://identityserver4.readthedocs.io/en/latest/topics/resources.html
                options.EmitStaticAudienceClaim = true;
            });

            // not recommended for production - you need to store your key material somewhere secure
            builder.AddDeveloperSigningCredential();

	        builder.AddProfileService<LocalUserProfileService>();

            var migrationsAssembly = typeof(Startup)
                .GetTypeInfo().Assembly.GetName().Name;

            builder.AddConfigurationStore(options =>
            {
                options.ConfigureDbContext = builder => 
                    builder.UseNpgsql(marvinIDPDataDBConnectionString,
                    options => options.MigrationsAssembly(migrationsAssembly));
            });

            builder.AddOperationalStore(options =>
            {
                options.ConfigureDbContext = builder => 
                    builder.UseNpgsql(marvinIDPDataDBConnectionString,
                    options => options.MigrationsAssembly(migrationsAssembly));
                options.EnableTokenCleanup = true;
            });

            services.AddAuthentication()
                .AddGoogle("Google", options =>
                {
                    options.SignInScheme = 
                        IdentityServerConstants.ExternalCookieAuthenticationScheme;

                    options.ClientId = 
                        Configuration["Google:ClientId"];
                    options.ClientSecret = 
                        Configuration["Google:ClientSecret"];
                    options.SaveTokens = true;
                });

            services.AddAuthentication()
                .AddMicrosoftAccount(options => {
                    options.SignInScheme = 
                        IdentityServerConstants.ExternalCookieAuthenticationScheme;

                    options.ClientId = 
                        Configuration["Microsoft:ClientId"];
                    options.ClientSecret = 
                        Configuration["Microsoft:ClientSecret"];
                    options.SaveTokens = true;
                });

            services.AddAuthentication(options =>
            {
                options.RequireAuthenticatedSignIn = false;

            }).AddCookie("idsrv.mfa");
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            InitializeDatabase(app);

            // uncomment if you want to add MVC
            app.UseStaticFiles();
            app.UseRouting();
            
            app.UseIdentityServer();

            // uncomment, if you want to add MVC
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
               endpoints.MapDefaultControllerRoute();
            });
        }

        private void InitializeDatabase(IApplicationBuilder app)
        {
            using (var serviceScope = app.ApplicationServices
                .GetService<IServiceScopeFactory>().CreateScope())
            {
                serviceScope.ServiceProvider
                    .GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

                var context = serviceScope.ServiceProvider
                    .GetRequiredService<ConfigurationDbContext>();

                context.Database.Migrate();

                if (!context.Clients.Any())
                {
                    foreach (var client in Config.Clients)
                    {
                        context.Clients.Add(client.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.IdentityResources.Any())
                {
                    foreach (var resource in Config.IdentityResources)
                    {
                        context.IdentityResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.ApiResources.Any())
                {
                    foreach (var resource in Config.Apis)
                    {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.ApiScopes.Any())
                {
                    foreach (var resource in Config.ApiScopes)
                    {
                        context.ApiScopes.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }                
            }
        }
    }
}
