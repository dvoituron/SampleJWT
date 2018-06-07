using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace MyJsonWebTokenApp.Tools
{
    public class JwtSecurityUser
    {
        #region CONSTRUCTORS

        public JwtSecurityUser(ClaimsPrincipal principal)
        {
            this.Name = principal?.Identity?.Name;
            this.IsAuthenticated = principal?.Identity?.IsAuthenticated == true;
            this.Roles = principal?.Claims?.Where(c => c.Type == ClaimTypes.Role).Select(c => Enum.Parse<JwtSecurityRole>(c.Value));

            this.NotBefore = EpochTimeToLocal(principal?.Claims?.FirstOrDefault(c => c.Type == "nbf").Value);
            this.Expiration = EpochTimeToLocal(principal?.Claims?.FirstOrDefault(c => c.Type == "exp").Value);
        }

        #endregion

        #region PROPERTIES

        public string Name { get; }

        public bool IsAuthenticated { get; }

        public IEnumerable<JwtSecurityRole> Roles { get; }

        public DateTime NotBefore { get; }

        public DateTime Expiration { get; }

        #endregion

        #region METHODS

        public bool IsMemberOf(JwtSecurityRole role)
        {
            return this.Roles?.Contains(role) == true;
        }

        #endregion

        #region PRIVATES

        private DateTime EpochTimeToLocal(string value)
        {
            if (String.IsNullOrEmpty(value))
            {
                return DateTime.Now;
            }
            else
            {
                //var expUtc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                //expUtc = expUtc.AddSeconds(Convert.ToDouble(exp));
                DateTime expUtc = Microsoft.IdentityModel.Tokens.EpochTime.DateTime(Convert.ToInt64(value));
                return expUtc.ToLocalTime();
            }
        }        

        #endregion
    }
}
