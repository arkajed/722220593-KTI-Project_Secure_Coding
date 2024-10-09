using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SampleSecureWeb.Data;
using SampleSecureWeb.Models;
using SampleSecureWeb.ViewModels;

namespace SampleSecureWeb.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUser _userData;

        public AccountController(IUser user)
        {
            _userData = user;
        }

        // GET: AccountController
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Register(RegistrationViewModel registrationViewModel)
        {
            try
            {
                if(ModelState.IsValid)
                {
                    if(!IsValidPassword(registrationViewModel.Password))
                    {
                        ModelState.AddModelError("Password", "Password harus minimal 12 karakter dan mengandung setidaknya satu huruf besar, satu huruf kecil, satu angka.");
                        return View(registrationViewModel);
                    };
                    
                    var user = new Models.User
                    {
                        Username = registrationViewModel.Username,
                        Password = registrationViewModel.Password,
                        RoleName = "contributor"
                    };
                    _userData.Registration(user);
                    return RedirectToAction("Index", "Home");
                }
            }
            catch (System.Exception ex)
            {
                ViewBag.Error = ex.Message;
            }
            return View(registrationViewModel);
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginViewModel loginViewModel)
        {
            try
            {
                loginViewModel.ReturnUrl = loginViewModel.ReturnUrl ?? Url.Content("~/");
                if(ModelState.IsValid)
                {
                    var user = new User
                    {
                        Username = loginViewModel.Username,
                        Password = loginViewModel.Password
                    };

                    var loginUser = _userData.Login(user);
                    if(loginUser == null)
                    {
                        ViewBag.Message = "Invalid login attempt.";
                        return View(loginViewModel);
                    }

                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.Username)
                    };
                    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        principal,
                        new AuthenticationProperties
                        {
                            IsPersistent = loginViewModel.RememberLogin
                        }
                    );

                    if(user != null)
                    {
                        return RedirectToAction("Index", "Home");
                    }
                }
            }
            catch (System.Exception ex)
            {
                ViewBag.Message = ex.Message;
            }
            return View(loginViewModel);
        }

        public ActionResult ChangePassword()
        {
            return View();
        }

        [HttpPost]
        public ActionResult ChangePassword(ChangePasswordViewModel changePasswordViewModel)
        {
            try
            {
                if(ModelState.IsValid)
                {
                    if(!IsValidPassword(changePasswordViewModel.NewPassword))
                    {
                        ModelState.AddModelError("NewPassword", "Password harus minimal 12 karakter dan mengandung setidaknya satu huruf besar, satu huruf kecil, satu angka.");
                        return View(changePasswordViewModel);
                    }

                    var username = User.Identity?.Name;
                    if(username == null)
                    {
                        return RedirectToAction("Login");
                    }

                    var user = _userData.GetUserByUsername(username); 
                    if (user == null || !BCrypt.Net.BCrypt.Verify(changePasswordViewModel.CurrentPassword, user.Password))
                    {
                        ModelState.AddModelError("CurrentPassword", "Kata sandi salah.");
                        return View(changePasswordViewModel);
                    }

                    user.Password = BCrypt.Net.BCrypt.HashPassword(changePasswordViewModel.NewPassword);
                    _userData.UpdateUser(user);
                    ViewBag.Message = "Kata sandi berhasil diubah!";
                    return RedirectToAction("Index", "Home");
                }
            }
            catch (System.Exception ex)
            {
                ViewBag.Error = ex.Message;
            }
            return View(changePasswordViewModel);
        }

        private bool IsValidPassword(string password)
        {
            // Periksa panjang minimum dan syarat karakter
            return password.Length >= 12 &&
                   Regex.IsMatch(password, @"[A-Z]") && // Setidaknya satu huruf besar
                   Regex.IsMatch(password, @"[a-z]") && // Setidaknya satu huruf kecil
                   Regex.IsMatch(password, @"[0-9]"); // Setidaknya satu digit
        }
    }
}
