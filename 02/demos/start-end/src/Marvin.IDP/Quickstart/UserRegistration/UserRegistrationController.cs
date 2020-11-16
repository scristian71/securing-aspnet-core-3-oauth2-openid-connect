using IdentityModel;
using IdentityServer4;
using IdentityServer4.Services;
using Marvin.IDP.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace Marvin.IDP.UserRegistration
{
    public class UserRegistrationController : Controller
    {
        private readonly ILocalUserService _localUserService;
        private readonly IIdentityServerInteractionService _interaction;

        public UserRegistrationController(
            ILocalUserService localUserService,
            IIdentityServerInteractionService interaction)
        {
            _localUserService = localUserService ??
                throw new ArgumentNullException(nameof(localUserService));
            _interaction = interaction ??
                throw new ArgumentNullException(nameof(interaction));
        }

        // [HttpGet]
        // public async Task<IActionResult> ActivateUser(string securityCode)
        // {
        //     if (await _localUserService.ActivateUser(securityCode))
        //     {
        //         ViewData["Message"] = "Your account was successfully activated.  " +
        //             "Navigate to your client application to log in.";
        //     }
        //     else
        //     {
        //         ViewData["Message"] = "Your account couldn't be activated, " +
        //             "please contact your administrator.";
        //     }

        //     await _localUserService.SaveChangesAsync();

        //     return View();
        // }

        [HttpGet]
        public IActionResult RegisterUser(string returnUrl)
        {
            var vm = new RegisterUserViewModel()
            { ReturnUrl = returnUrl };
            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegisterUser(RegisterUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var userToCreate = new Entities.User
            {
                Username = model.UserName,
                Subject = Guid.NewGuid().ToString(),
                Email = model.Email,
                Active = false
            };

            userToCreate.Claims.Add(new Entities.UserClaim()
            {
                Type = "country",
                Value = model.Country
            });

            userToCreate.Claims.Add(new Entities.UserClaim()
            {
                Type = JwtClaimTypes.Address,
                Value = model.Address
            });

            userToCreate.Claims.Add(new Entities.UserClaim()
            {
                Type = JwtClaimTypes.GivenName,
                Value = model.GivenName
            });

            userToCreate.Claims.Add(new Entities.UserClaim()
            {
                Type = JwtClaimTypes.FamilyName,
                Value = model.FamilyName
            });

            _localUserService.AddUser(userToCreate, model.Password);

            await _localUserService.SaveChangesAsync();

            // create an activation link
            // var link = Url.ActionLink("ActivateUser", "UserRegistration", 
            //     new { securityCode = userToCreate.SecurityCode });

            // Debug.WriteLine(link);

            // return View("ActivationCodeSent");

            //// log the user in
            // issue authentication cookie with subject ID and username
            var isuser = new IdentityServerUser(userToCreate.Subject)
            {
                DisplayName = userToCreate.Username
            };
            //don't add authentication props now        
            await HttpContext.SignInAsync(isuser, null);

            // continue with the flow     
            if (_interaction.IsValidReturnUrl(model.ReturnUrl)
               || Url.IsLocalUrl(model.ReturnUrl))
            {
               return Redirect(model.ReturnUrl);
            }

            return Redirect("~/");

        }

    }

}
