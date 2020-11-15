// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace Marvin.IDP
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            { 
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Address(),
                new IdentityResource(
                    "country",
                    "The country you're living in",
                    new List<string>() { "country" })
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new List<ApiScope>
                {
                    new ApiScope(name: "imagegalleryapi.role",   displayName: "Read image gallery data.")
                };

        public static IEnumerable<ApiResource> Apis =>
            new ApiResource[] 
            {
                new ApiResource(
                    "imagegalleryapi", 
                    "Image Gallery API")
                    {
                        Scopes = {"imagegalleryapi.role"},
			            ApiSecrets = { new Secret("apisecret".Sha256()) }
                    }
            };
        
        public static IEnumerable<Client> Clients =>
            new Client[] 
            { 
                new Client
                {
                    AccessTokenType = AccessTokenType.Reference,
                    AccessTokenLifetime = 120,
                    AllowOfflineAccess = true,
                    AbsoluteRefreshTokenLifetime = 5 * 24 * 3600, //5 days
                    RefreshTokenExpiration = TokenExpiration.Sliding,
                    UpdateAccessTokenClaimsOnRefresh = true, //update token on claims change
                    ClientName = "Image Gallery", 
                    ClientId = "imagegalleryclient",
                    AllowedGrantTypes = GrantTypes.Code,
                    RequirePkce = true,
                    RedirectUris = new List<string>()
                    {
                        "https://localhost:5001/signin-oidc"
                    },
                    PostLogoutRedirectUris = new List<string>()
                    {
                        "https://localhost:5001/signout-callback-oidc"
                    },
                    AllowedScopes = 
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Address,
                        "imagegalleryapi.role",
                        "country"
                    },
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    }
                } 
            };
    }
}
