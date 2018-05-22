using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PtcApi.Model;

namespace PtcApi.Controllers
{
    [Route("api/[controller]")]
    public class SecurityController : BaseApiController
    {
        private readonly JwtSettings _jwtSettings;


        public SecurityController(JwtSettings jwtSettings)
        {
            _jwtSettings = jwtSettings;
        }
        [HttpPost("login")]
        public IActionResult Login([FromBody] AppUser user)
        {
            IActionResult ret = null;
            AppUserAuth auth = new AppUserAuth();
            SecurityManager mgr = new SecurityManager(_jwtSettings);

            auth = mgr.ValidateUser(user);
            ret = auth.IsAuthenticated 
                ? StatusCode(StatusCodes.Status200OK, auth) 
                : StatusCode(StatusCodes.Status404NotFound, "Invalid User Name/Password");

            return ret;
        }
    }
}