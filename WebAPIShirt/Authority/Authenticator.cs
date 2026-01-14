using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
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
    }

}
