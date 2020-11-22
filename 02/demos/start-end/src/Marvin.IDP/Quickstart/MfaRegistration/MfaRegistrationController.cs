using IdentityModel;
using Marvin.IDP.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Marvin.IDP
{
    public class MfaRegistrationController : Controller
    {
        private readonly ILocalUserService _localUserService;
        private readonly char[] chars =
           "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

        public MfaRegistrationController(
            ILocalUserService localUserService)
        {
            _localUserService = localUserService ??
                throw new ArgumentNullException(nameof(localUserService));
        }

        [HttpGet]
        public async Task<IActionResult> RegisterForMfa(string returnUrl)
        {
            var secret = string.Empty;

            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] tokenData = new byte[64];
                rng.GetBytes(tokenData);

                var result = new StringBuilder(16);
                for (int i = 0; i < 16; i++)
                {
                    var rnd = BitConverter.ToUInt32(tokenData, i * 4);
                    var idx = rnd % chars.Length;

                    result.Append(chars[idx]);
                }

                secret = result.ToString();
            }

            // read identity from the temporary cookie
            var resultIdent = await HttpContext.AuthenticateAsync("idsrv.mfa");
            if (resultIdent?.Succeeded != true)
            {
                throw new Exception("MFA authentication error");
            }
            var subject = resultIdent.Principal.FindFirst(JwtClaimTypes.Subject)?.Value;

            var user = await _localUserService.GetUserBySubjectAsync(subject);

            var keyUri = string.Format(
               "otpauth://totp/{0}:{1}?secret={2}&issuer={0}",
               WebUtility.UrlEncode("Marvin"),
               WebUtility.UrlEncode(user.Email),
               secret);

            var vm = new RegisterForMfaViewModel()
            {
                KeyUri = keyUri,
                Secret = secret,
                ReturnUrl = returnUrl
            };

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegisterForMfa(
          RegisterForMfaViewModel model)
        {
            if (ModelState.IsValid)
            {
                // read identity from the temporary cookie
                var resultIdent = await HttpContext.AuthenticateAsync("idsrv.mfa");
                if (resultIdent?.Succeeded != true)
                {
                    throw new Exception("MFA authentication error");
                }
                var subject = resultIdent.Principal.FindFirst(JwtClaimTypes.Subject)?.Value;

                if (await _localUserService.AddUserSecret(subject, "TOTP", model.Secret))
                {
                    await _localUserService.SaveChangesAsync();
                    return Redirect(model.ReturnUrl);

                }
                else
                {
                    throw new Exception("MFA registration error");
                }

            }
            return View(model);
        }
    }
}