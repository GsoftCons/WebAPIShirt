using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using static System.Net.Mime.MediaTypeNames;

namespace WebAPIShirt.Authority
{
    public static class Authenticator
    {
        public static bool Authenticate(string clientId, string secret)
        {
            var app = AppRepository.GetApplicationByClientId(clientId);
            if (app == null)
                return false;

            return (app.ClientId == clientId && app.Secret == secret);
        }

    public static string  CreateToken(string clientId, DateTime expiresAt, string strSecretKey)
        {
            // Algorithm
            // Signing Key
            // Payload (claims)

            //Algorithm
            var signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(strSecretKey)),
                SecurityAlgorithms.HmacSha256Signature);

            // Payload (claims)
            var app = AppRepository.GetApplicationByClientId(clientId);
            var claimsDictionary = new Dictionary<string, object>
            {
                { "AppName", app?.ApplicationName?? string.Empty },
                { "Read", (app.Scopes ?? string.Empty).Contains("read") ? "true":"false" },
                { "Write", (app.Scopes ?? string.Empty).Contains("write") ? "true":"false" },
            };


            var tokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = signingCredentials,
                Claims = claimsDictionary,
                Expires = expiresAt,
                NotBefore = DateTime.UtcNow,
            };

            var tokenHandler = new JsonWebTokenHandler();
            return tokenHandler.CreateToken(tokenDescriptor);
        }

        internal static async Task<bool> VerifyTokenAsync(string tokenString, string securityKey)
        {
            if(string.IsNullOrEmpty(tokenString) || string.IsNullOrEmpty(securityKey)) 
                return false;

            var keyBytes = System.Text.Encoding.UTF8.GetBytes(securityKey);
            var tokenHandler = new JsonWebTokenHandler();

            var validationParameter = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            try
            {
                var result = await tokenHandler.ValidateTokenAsync(tokenString, validationParameter);
                return result.IsValid;
            }

            catch(SecurityTokenMalformedException)
            {
                return false;
            }

            catch (Exception)
            {
                throw;
            }



        }
    }

}
