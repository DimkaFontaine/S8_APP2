using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using Sanssoussi.Areas.Identity.Data;

namespace Sanssoussi.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        private readonly ILogger<LoginModel> _logger;

        private readonly SqliteConnection _dbConnection;

        private readonly SignInManager<SanssoussiUser> _signInManager;

        private readonly UserManager<SanssoussiUser> _userManager;

        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public LoginModel(
            SignInManager<SanssoussiUser> signInManager,
            ILogger<LoginModel> logger,
            UserManager<SanssoussiUser> userManager,
            IConfiguration configuration)
        {
            this._userManager = userManager;
            this._signInManager = signInManager;
            this._logger = logger;
            this._dbConnection = new SqliteConnection(configuration.GetConnectionString("SanssoussiContextConnection"));
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(this.ErrorMessage))
            {
                this.ModelState.AddModelError(string.Empty, this.ErrorMessage);
            }

            returnUrl = returnUrl ?? this.Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await this.HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            this.ExternalLogins = (await this._signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            this.ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl = returnUrl ?? this.Url.Content("~/");

            if (this.ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await this._signInManager.PasswordSignInAsync(
                                 this.Input.Email,
                                 this.Input.Password,
                                 this.Input.RememberMe,
                                 lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    this._logger.LogInformation("User logged in.");
                    return this.LocalRedirect(returnUrl);
                }

                if (result.RequiresTwoFactor)
                {
                    return this.RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = this.Input.RememberMe });
                }

                if (result.IsLockedOut)
                {
                    this._logger.LogWarning("User account locked out.");
                    return this.RedirectToPage("./Lockout");
                }

                var cmdCheckFailedCountText = $"Select AccessFailedCount from AspNetUsers where Email = @userEmail";
                var cmdCheckFailedCount = new SqliteCommand(cmdCheckFailedCountText, this._dbConnection);
                cmdCheckFailedCount.Parameters.Add("@userEmail", SqliteType.Text);
                cmdCheckFailedCount.Parameters["@userEmail"].Value = this.Input.Email;

                this._dbConnection.Open();

                var rd = await cmdCheckFailedCount.ExecuteReaderAsync();
                int failCount = 0;

                while (rd.Read())
                {
                    failCount = Int16.Parse(rd.GetString(0));
                }
                rd.Close();


                var cmdSetFailedCountText = $"UPDATE AspNetUsers SET AccessFailedCount = @failCount WHERE Email = @userEmail";
                var cmdSetFailedCount = new SqliteCommand(cmdSetFailedCountText, this._dbConnection);
                cmdSetFailedCount.Parameters.Add("@failCount", SqliteType.Integer);
                cmdSetFailedCount.Parameters.Add("@userEmail", SqliteType.Text);
                cmdSetFailedCount.Parameters["@failCount"].Value = failCount + 1;
                cmdSetFailedCount.Parameters["@userEmail"].Value = this.Input.Email;
                var rd2 = await cmdSetFailedCount.ExecuteReaderAsync();

                rd2.Close();
                this._dbConnection.Close();


                this.ModelState.AddModelError(string.Empty, "Invalid login attempt. (" + failCount + ")");

                return this.Page();
            }

            // If we got this far, something failed, redisplay form
            return this.Page();
        }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }
    }
}