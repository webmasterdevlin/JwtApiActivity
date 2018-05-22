using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace PtcApi.Model
{
    public class SecurityManager
    {
        private readonly JwtSettings _jwtSettings;

        public SecurityManager(JwtSettings jwtSettings)
        {
            _jwtSettings = jwtSettings;
        }
        
        public AppUserAuth ValidateUser(AppUser user)
        {
            var ret = new AppUserAuth();
            AppUser authUser = null;

            using (var db = new PtcDbContext())    
            {
                // Attempt to validate user
                authUser = db.Users.FirstOrDefault(u => u.Password == user.Password);
            }

            if (authUser != null)
            {
                // Build user security object
                ret = BuildUserAuthObject(authUser);
            }

            return ret;
        }

        protected List<AppUserClaim> GetUserClaims(AppUser authUser)
        {
            var list = new List<AppUserClaim>();
            try
            {
                using (var db = new PtcDbContext())
                {
                    list = db.Claims.Where(u => u.UserId == authUser.UserId).ToList();
                }
            }
            catch (Exception e)
            {
                throw new Exception("Exception trying to retrieve user claims.", e);
            }

            return list;
        }

        protected AppUserAuth BuildUserAuthObject(AppUser authUser)
        {
            var ret = new AppUserAuth();
            var claims = new List<AppUserClaim>();
            
            // Set User Properties
            ret.UserName = authUser.UserName;
            ret.IsAuthenticated = true;
            ret.BearerToken = new Guid().ToString();

           
            
            // Get all claims for this user
            ret.Claims = GetUserClaims(authUser);
            // ret.Claims = GetUserClaims(authUser);
            
            // Set JWT bearer token 
            ret.BearerToken = BuildJwtToken(ret);
            return ret;
        }

        protected string BuildJwtToken(AppUserAuth userAuth)
        {
            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));

            // Create standard JWT claims
            var jwtClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userAuth.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            // Add custom claims
            jwtClaims.Add(new Claim("isAuthenticated", userAuth.IsAuthenticated.ToString().ToLower()));

            // Add custom claims from the Claim array
            foreach (var claim in userAuth.Claims)
            {
                jwtClaims.Add(new Claim(claim.ClaimType, claim.ClaimValue));
            }

            // Create the JwtSecurityToken object
            var token = new JwtSecurityToken(
                issuer:_jwtSettings.Issuer, 
                audience:_jwtSettings.Audience,
                claims:jwtClaims,
                notBefore:DateTime.UtcNow,
                expires:DateTime.UtcNow.AddMinutes(_jwtSettings.MinutesToExpiration),
                signingCredentials:new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
                );

            // Create a string representation of the JWT token
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}