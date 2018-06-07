using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace MyJsonWebTokenApp.Tools
{
    /// <summary>
    /// Tools and methods to manage a JWT Security Token
    /// </summary>
    public static class JwtSecurityManager
    {
        private static Dictionary<string, SymmetricSecurityKey> _listOfSymetricKeys = new Dictionary<string, SymmetricSecurityKey>();

        /// <summary>
        /// Decrypt the current JWT Token 'stored' in the Controller.User property.
        /// </summary>
        /// <param name="controller"></param>
        /// <returns></returns>
        public static JwtSecurityUser UserJwt(this ControllerBase controller)
        {
            return new JwtSecurityUser(controller.User);
        }

        /// <summary>
        /// Add an Authentication service to the IoC of ASP.NET
        /// </summary>
        /// <param name="serviceCollection"></param>
        public static void AddJwtAuthentication(this IServiceCollection serviceCollection, string secretKey)
        {
            SymmetricSecurityKey securityKey = GetOrAddSecurityKey(secretKey);

            // Configure the JWT Authentication Service
            serviceCollection.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "JwtBearer";
                options.DefaultChallengeScheme = "JwtBearer";
            })
            .AddJwtBearer("JwtBearer", jwtOptions =>
            {
                jwtOptions.TokenValidationParameters = new TokenValidationParameters()
                {
                    // The SigningKey is defined in the TokenController class
                    IssuerSigningKey = securityKey,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true
                };
            });
        }

        /// <summary>
        /// Generate a Token with expiration date and Claim meta-data.
        /// And sign the token with the <paramref name="secretKey"/>
        /// </summary>
        /// <param name="secretKey"></param>
        /// <param name="jwtExpirationMinutes"></param>
        /// <param name="username"></param>
        /// <param name="memberOfRole"></param>
        /// <returns></returns>
        public static string GenerateToken(string secretKey, int jwtExpirationMinutes, string username, JwtSecurityRole memberOfRoles)
        {
            return GenerateToken(controller: null, 
                                 secretKey: secretKey, 
                                 jwtExpirationMinutes: jwtExpirationMinutes, 
                                 username: username,
                                 memberOfRoles: new JwtSecurityRole[] { memberOfRoles });
        }

        /// <summary>
        /// Generate a Token with expiration date and Claim meta-data.
        /// And sign the token with the <paramref name="secretKey"/>
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="secretKey"></param>
        /// <param name="jwtExpirationMinutes"></param>
        /// <param name="username"></param>
        /// <param name="memberOfRoles"></param>
        /// <returns></returns>
        public static string GenerateToken(string secretKey, int jwtExpirationMinutes, string username, IEnumerable<JwtSecurityRole> memberOfRoles)
        {
            return GenerateToken(controller: null, 
                                 secretKey: secretKey, 
                                 jwtExpirationMinutes: jwtExpirationMinutes, 
                                 username: username, 
                                 memberOfRoles: memberOfRoles);
        }

        /// <summary>
        /// Generate a Token with expiration date and Claim meta-data.
        /// And sign the token with the <paramref name="secretKey"/>
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="secretKey"></param>
        /// <param name="jwtExpirationMinutes"></param>
        /// <param name="username"></param>
        /// <param name="memberOfRole"></param>
        /// <returns></returns>
        public static string GenerateToken(this ControllerBase controller, string secretKey, int jwtExpirationMinutes, string username, JwtSecurityRole memberOfRoles)
        {
            return GenerateToken(controller, secretKey, jwtExpirationMinutes, username, new JwtSecurityRole[] { memberOfRoles });
        }

        /// <summary>
        /// Generate a Token with expiration date and Claim meta-data.
        /// And sign the token with the <paramref name="secretKey"/>
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="secretKey"></param>
        /// <param name="jwtExpirationMinutes"></param>
        /// <param name="username"></param>
        /// <param name="memberOfRoles"></param>
        /// <returns></returns>
        public static string GenerateToken(this ControllerBase controller, string secretKey, int jwtExpirationMinutes, string username, IEnumerable<JwtSecurityRole> memberOfRoles)
        {
            SymmetricSecurityKey securityKey = GetOrAddSecurityKey(secretKey);

            // Username and list of roles
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, username));
            claims.AddRange(memberOfRoles.Select(role => new Claim(ClaimTypes.Role, Enum.GetName(typeof(JwtSecurityRole), role))));

            var token = new JwtSecurityToken(
                    claims: claims,
                    notBefore: new DateTimeOffset(DateTime.Now).DateTime,
                    expires: new DateTimeOffset(DateTime.Now.AddMinutes(jwtExpirationMinutes)).DateTime,
                    signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Renew the active Token and returns a new valid Token with same claims data.
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        public static string RenewToken(this ControllerBase controller, string secretKey)
        {
            JwtSecurityUser user = UserJwt(controller);

            int jwtExpirationMinutes = Convert.ToInt32((user.Expiration - user.NotBefore).TotalMinutes);

            return GenerateToken(secretKey, jwtExpirationMinutes, user.Name, user.Roles);
        }

        private static SymmetricSecurityKey GetOrAddSecurityKey(string secretKey)
        {
            if (secretKey.Length != 32)
                throw new ArgumentException("The SecretKey must be a string of 32 chars", "secretKey");

            if (_listOfSymetricKeys.ContainsKey(secretKey))
                return _listOfSymetricKeys[secretKey];

            var newKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            _listOfSymetricKeys.Add(secretKey, newKey);
            return newKey;
        }
    }
}
