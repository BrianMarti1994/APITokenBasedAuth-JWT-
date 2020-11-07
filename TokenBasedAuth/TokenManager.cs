using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace TokenBasedAuth
{
    public class TokenManager
    {

        private static string Secret = "YnJpYW4xMjM0NTY3ODlDb2RlQnJpYW4=";

        public static string GenerateToken(string userName)
        {
            //Convert Secret to Array
            byte[] key = Convert.FromBase64String(Secret);

            //algorithm to generate key
            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(key);
            SecurityTokenDescriptor description = new SecurityTokenDescriptor
                {

                Subject = new System.Security.Claims.ClaimsIdentity(claims: new[] { new Claim(type:ClaimTypes.Name ,value:userName)}),
                Expires = DateTime.UtcNow.AddMinutes(3),
                SigningCredentials = new SigningCredentials(securityKey,algorithm:SecurityAlgorithms.HmacSha256Signature)
            };
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = handler.CreateJwtSecurityToken(description);
            return handler.WriteToken(token);
        }

        public static ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
                if (token==null)
                {
                    return null;
                }
                else
                {
                    byte[] key = Convert.FromBase64String(Secret);
                    TokenValidationParameters parameters = new TokenValidationParameters()
                    {
                        RequireExpirationTime = true,
                        ValidateIssuer = false,
                        ValidateAudience =false,
                        IssuerSigningKey=new SymmetricSecurityKey(key)
                    
                    };
                    SecurityToken securityToken;
                    ClaimsPrincipal principal = tokenHandler.ValidateToken(token, parameters, out securityToken);
                    return principal;

                }
            }
            catch (Exception)
            {

                return null;
            }
        }

        public static string ValidateToken(string token)
        {
            string userName = string.Empty;
            ClaimsPrincipal principal = GetPrincipal(token);
            if (principal == null)
                return null;
            ClaimsIdentity identity = null;
            
            try
            {
                identity = (ClaimsIdentity)principal.Identity;
            }
            catch (Exception)
            {

                return null;
            }
            Claim usernameClaims = identity.FindFirst(type: ClaimTypes.Name);
            userName = usernameClaims.Value;
            return userName;
        }
    }
}