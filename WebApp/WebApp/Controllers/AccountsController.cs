using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using WebApp.Data;
using WebApp.Models;

namespace WebApp.Controllers
{
    [Authorize(Roles = "Admin")]

    public class AccountsController : Controller
    {
        private readonly WebAppContext _context;

        public AccountsController(WebAppContext context)
        {
            _context = context;
        }

        // GET: Accounts
        [HttpGet("Accounts/{Page?}/{PageSize?}")]
        public async Task<IActionResult> Index(int Page = 1, int PageSize = 10, string search = null)
        {
            if (search != null)
            {
                ViewData["ValueSearch"] = search;
                using (var command = _context.Database.GetDbConnection().CreateCommand())
                {
                    command.CommandText = $"SELECT dbo.func_CountSearchAccountPage('{search}')";
                    _context.Database.OpenConnection();
                    using (var result = command.ExecuteReader())
                    {
                        while (result.Read())
                        {
                            ViewData["TotalPage"] = Math.Round((float)result.GetInt32(0) / PageSize + 0.5f);
                        }
                    }
                }
            }
            else
            {
                ViewData["TotalPage"] = Math.Round((float)(await _context.Accounts.CountAsync() / PageSize + 0.5f));
            }
            ViewData["PageCurrent"] = Page;
            ViewData["PageSize"] = PageSize;
            ViewData["PermissionList"] = _context.Permissions.ToArray();

            List<Account> accounts = new List<Account>();
            if (search != null)
            {
                accounts = await _context.Accounts.FromSqlRaw($"SELECT * FROM dbo.func_SearchAccountPage('{search}',{Page},{PageSize})").ToListAsync();
            }
            else
            {
                accounts = await _context.Accounts.FromSqlRaw($"SELECT * FROM dbo.func_GetAccountPage({PageSize},{Page})").ToListAsync();
            }
            return View(accounts);
        }

        // GET: Accounts/Details/5
        [Route("Accounts/Details/{id?}")]
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var account = await _context.Accounts
                .FirstOrDefaultAsync(m => m.AccountId == id);
            if (account == null)
            {
                return NotFound();
            }

            return View(account);
        }

        // GET: Accounts/Create
        [Route("Accounts/Create")]
        public async Task<IActionResult> CreateAsync()
        {
            await CreatePermissionListAsync(null);

            return View();
        }

        // POST: Accounts/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("AccountId,UserName,Password,FullName")] Account account, int Permission)
        {
            account.PermissionId = Permission;

            if (ModelState.IsValid)
            {
                _context.Add(account);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(account);
        }

        // GET: Accounts/Edit/5
        [Route("Accounts/Edit/{id?}")]
        public async Task<IActionResult> Edit(int? id)
        {
            await CreatePermissionListAsync(id);

            if (id == null)
            {
                return NotFound();
            }

            var account = await _context.Accounts.FindAsync(id);
            if (account == null)
            {
                return NotFound();
            }
            return View(account);
        }

        // POST: Accounts/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route("Accounts/Edit/{id?}")]
        public async Task<IActionResult> Edit(int id, [Bind("AccountId,UserName,Password,FullName")] Account account, int Permission)
        {
            account.PermissionId = Permission;

            if (id != account.AccountId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(account);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!AccountExists(account.AccountId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(account);
        }

        // GET: Accounts/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var account = await _context.Accounts
                .FirstOrDefaultAsync(m => m.AccountId == id);
            if (account == null)
            {
                return NotFound();
            }

            return View(account);
        }

        // POST: Accounts/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var account = await _context.Accounts.FindAsync(id);
            _context.Accounts.Remove(account);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        [Route("/Login")]
        [AllowAnonymous]
        public ActionResult Login(string ReturnUrl)
        {
            ViewBag.ReturnUrl = ReturnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string UserName, string Password, string ReturnUrl)
        {
            ViewBag.ReturnUrl = ReturnUrl;
            Account account = _context.Accounts.Where(s => s.UserName == UserName && s.Password == Password).FirstOrDefault();

            if (account != null)
            {
                account.Permission = _context.Permissions.Where(s => s.PermissionId == account.PermissionId).FirstOrDefault();

                var claims = new List<Claim>();
                claims.Add(new Claim("Id", account.AccountId.ToString()));
                claims.Add(new Claim(ClaimTypes.Name, account.FullName));
                claims.Add(new Claim(ClaimTypes.Role, account.Permission.PermissionName));

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

                var props = new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(1)
                };

                await HttpContext.SignInAsync(claimsPrincipal, props);

                return Redirect(ReturnUrl == null ? "/" : ReturnUrl);
            }
            TempData["Error"] = "Username or Password is not vaild";

            // generate a 128-bit salt using a cryptographically strong random sequence of nonzero values
            //byte[] salt = new byte[128 / 8];
            //using (var rngCsp = new RNGCryptoServiceProvider())
            //{
            //    rngCsp.GetNonZeroBytes(salt);
            //}
            //salt = System.Text.Encoding.ASCII.GetBytes("uMb8bCC25vfSb/AMhFbIFQ==");
            //Console.WriteLine($"Salt: {Convert.ToBase64String(salt)}");

            //// derive a 256-bit subkey (use HMACSHA256 with 100,000 iterations)
            //string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            //    password: Password,
            //    salt: salt,
            //    prf: KeyDerivationPrf.HMACSHA256,
            //    iterationCount: 100000,
            //    numBytesRequested: 256 / 8));
            //string hashed2 = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            //    password: Password,
            //    salt: salt,
            //    prf: KeyDerivationPrf.HMACSHA256,
            //    iterationCount: 100000,
            //    numBytesRequested: 256 / 8));
            //Console.WriteLine($"Hashed: {hashed}");
            //Console.WriteLine($"Hashed: {hashed2}");
            return View("Login");
        }

        [Route("/Logout")]
        [AllowAnonymous]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [ActionName("Manager")]
        [Route("Accounts/Manager")]
        [AllowAnonymous]
        public IActionResult Manager()
        {
            return View();
        }

        [ActionName("ChangeFullName")]
        [AllowAnonymous]
        public async Task<IActionResult> ChangeFullNameAsync(string FullName)
        {
            if (!string.IsNullOrEmpty(FullName))
            {
                Account account = _context.Accounts.Find(int.Parse(User.Claims.First(x => x.Type == "Id").Value));
                account.FullName = FullName;
                _context.Accounts.Update(account);
                _context.SaveChanges();
                TempData["NotiFullName"] = "Change full name successful";

                var indentity = User.Identity as ClaimsIdentity;
                indentity.RemoveClaim(indentity.FindFirst(ClaimTypes.Name));
                indentity.AddClaim(new Claim(ClaimTypes.Name, FullName));

                var principal = new ClaimsPrincipal(indentity);
                await HttpContext.SignOutAsync();
                await HttpContext.SignInAsync(principal);
            }
            else
            {
                TempData["ErrorFullName"] = "Full Name is empty";
            }
            return RedirectToAction("Manager");
        }

        [ActionName("ChangePassword")]
        [AllowAnonymous]
        public IActionResult ChangePassword(string Password, string NewPassword, string ConfirmNewPassword)
        {
            if (string.IsNullOrEmpty(Password) || string.IsNullOrEmpty(NewPassword) || string.IsNullOrEmpty(ConfirmNewPassword))
            {
                TempData["ErrorPassword"] = "Some field is empty";
            }
            else
            {
                if (NewPassword != ConfirmNewPassword)
                {
                    TempData["ErrorPassword"] = "Confirm password incorrect";
                }
                else
                {
                    Account account = _context.Accounts.Find(int.Parse(User.Claims.First(x => x.Type == "Id").Value));
                    if (Password != account.Password)
                    {
                        TempData["ErrorPassword"] = "Old password incorrect";
                    }
                    else
                    {
                        account.Password = NewPassword;
                        _context.Accounts.Update(account);
                        _context.SaveChanges();
                        TempData["NotiPassword"] = "Change password successful";
                    }
                }
            }
            return RedirectToAction("Manager");
        }

        [AllowAnonymous]
        [Route("/Register")]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [Route("/Register")]
        [AllowAnonymous]
        public IActionResult Register([Bind("UserName,FullName,Password")] Account account)
        {
            var check = _context.Accounts.Where(s => s.UserName == account.UserName).FirstOrDefault();
            if (check != null)
            {
                ViewBag.Error = "User name is taken. Try another";
                return View(account);
            }
            account.PermissionId = 2;
            _context.Accounts.Add(account);
            _context.SaveChanges();
            return RedirectToAction("Login");
        }

        private bool AccountExists(int id)
        {
            return _context.Accounts.Any(e => e.AccountId == id);
        }

        private async Task CreatePermissionListAsync(int? id)
        {
            List<SelectListItem> selectLists = new List<SelectListItem>();

            int idPermission = id == null ? -1 : _context.Accounts.Find(id).PermissionId;

            foreach (Permission item in await _context.Permissions.ToArrayAsync())
            {
                if (item.PermissionId == idPermission)
                    selectLists.Insert(0, new SelectListItem(item.PermissionName, item.PermissionId.ToString(), true));
                else
                    selectLists.Add(new SelectListItem(item.PermissionName, item.PermissionId.ToString(), false));
            }

            ViewData["PermissionList"] = selectLists;
        }
    }
}
