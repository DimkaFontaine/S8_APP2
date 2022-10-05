using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using Sanssoussi.Areas.Identity.Data;
using Sanssoussi.Models;

namespace Sanssoussi.Controllers
{
    public class HomeController : Controller
    {
        private readonly SqliteConnection _dbConnection;

        private readonly ILogger<HomeController> _logger;

        private readonly UserManager<SanssoussiUser> _userManager;

        public HomeController(ILogger<HomeController> logger, UserManager<SanssoussiUser> userManager, IConfiguration configuration)
        {
            this._logger = logger;
            this._userManager = userManager;
            this._dbConnection = new SqliteConnection(configuration.GetConnectionString("SanssoussiContextConnection"));
        }

        public IActionResult Index()
        {
            this.ViewData["Message"] = "Parce que marcher devrait se faire SansSoussi";
            return this.View();
        }

        [HttpGet]
        public async Task<IActionResult> Comments()
        {
            var comments = new List<string>();
            SqliteDataReader rd = null;

            var user = await this._userManager.GetUserAsync(this.User);
            if (user == null)
            {
                return this.View(comments);
            }
            try
            { 
                var cmdText = $"Select Comment from Comments where UserId = @userId";
                var cmd = new SqliteCommand(cmdText, this._dbConnection);
                cmd.Parameters.Add("@userId", SqliteType.Text);
                cmd.Parameters["@userId"].Value = user.Id;


                this._dbConnection.Open();

                rd = await cmd.ExecuteReaderAsync();

                while (rd.Read())
                {
                    comments.Add(rd.GetString(0));
                }
            }
            catch (SqliteException ex)
            {
                var code = "(" + ex.SqliteErrorCode + ") " + ex.SqliteExtendedErrorCode;
                this._logger.LogError("Une erreur est survenue lors de la selection de commentaire dans la base de données. " + code);
            }
            finally
            {
                if (rd != null) rd.Close();
                if (this._dbConnection != null) this._dbConnection.Close();
            }

            rd.Close();
            this._dbConnection.Close();


            return this.View(comments);
        }

        [HttpPost]
        public async Task<IActionResult> Comments(string comment)
        {
            var user = await this._userManager.GetUserAsync(this.User);

            if (user == null)
            {
                throw new InvalidOperationException("Vous devez vous connecter");
            }

            try
            {
                var cmd = new SqliteCommand(
                    $"insert into Comments (UserId, CommentId, Comment) Values (@userId, @guid, @comment)",
                    this._dbConnection);

                cmd.Parameters.AddWithValue("@userId", user.Id);
                cmd.Parameters.AddWithValue("@guid", Guid.NewGuid());
                cmd.Parameters.AddWithValue("@comment", HttpUtility.HtmlEncode(comment));

                this._dbConnection.Open();

                await cmd.ExecuteNonQueryAsync();
            }
            catch (SqliteException ex)
            {
                var code = "(" + ex.SqliteErrorCode + ") " + ex.SqliteExtendedErrorCode;
                this._logger.LogError("Une erreur est survenue lors de l'ajout de commentaire. " + code);
            }
            finally
            {
                if (this._dbConnection != null) this._dbConnection.Close();
            }

            return this.Ok("Commentaire ajouté");
        }

        public async Task<IActionResult> Search(string searchData)
        {
            var searchResults = new List<string>();
            SqliteDataReader rd = null;

            var user = await this._userManager.GetUserAsync(this.User);
            if (user == null || string.IsNullOrEmpty(searchData))
            {
                return this.View(searchResults);
            }
            try
            {
                var cmd = new SqliteCommand(
                    $"Select Comment from Comments where UserId = @userId and Comment like @searchData",
                    this._dbConnection);

                cmd.Parameters.Add("@userId", SqliteType.Text);
                cmd.Parameters.Add("@searchData", SqliteType.Text);

                cmd.Parameters["@userId"].Value = user.Id;
                cmd.Parameters["@searchData"].Value = searchData;

                this._dbConnection.Open();

                rd = await cmd.ExecuteReaderAsync();

                while (rd.Read())
                {
                    searchResults.Add(rd.GetString(0));
                }
            }
            catch (SqliteException ex)
            {
                var code = "(" + ex.SqliteErrorCode + ") " + ex.SqliteExtendedErrorCode;
                this._logger.LogError("Une erreur est survenue lors de la recherche de commentaire. " + code);
            }
            finally
            {
                if(rd != null) rd.Close();
                if(this._dbConnection != null) this._dbConnection.Close();
            }
            return this.View(searchResults);
        }

        public IActionResult About()
        {
            return this.View();
        }

        public IActionResult Privacy()
        {
            return this.View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return this.View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? this.HttpContext.TraceIdentifier });
        }

        [HttpGet]
        public IActionResult Emails()
        {
            return this.View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Emails(object form)
        {
            var searchResults = new List<string>();
            SqliteDataReader rd = null;

            var user = await this._userManager.GetUserAsync(this.User);
            var roles = await this._userManager.GetRolesAsync(user);
            if (roles.Contains("admin"))
            {
                try
                {
                    var cmd = new SqliteCommand("select Email from AspNetUsers", this._dbConnection);
                    this._dbConnection.Open();
                    rd = await cmd.ExecuteReaderAsync();
                    while (rd.Read())
                    {
                        searchResults.Add(rd.GetString(0));
                    }
                }
                catch (SqliteException ex)
                {
                    var code = "(" + ex.SqliteErrorCode + ") " + ex.SqliteExtendedErrorCode;
                    this._logger.LogError("Une erreur est survenue lors de la recherche de courriel. " + code);
                }
                finally
                {
                    if(rd != null) rd.Close();
                    if(this._dbConnection != null) this._dbConnection.Close();
                }
            }
            return this.Json(searchResults);
        }
    }
}