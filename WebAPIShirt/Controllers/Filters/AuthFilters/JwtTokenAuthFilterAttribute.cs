using Microsoft.AspNetCore.Mvc.Filters;
using System.Diagnostics.Eventing.Reader;
using WebAPIShirt.Authority;

namespace WebAPIShirt.Controllers.Filters.AuthFilters
{
    public class JwtTokenAuthFilterAttribute : Attribute, IAsyncAuthorizationFilter
    {
        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            //1 get auth header from request
            if(!context.HttpContext.Request.Headers.TryGetValue("Authorization", out var authHeader))
            {
                context.Result = new Microsoft.AspNetCore.Mvc.UnauthorizedResult();
                return;
            }

            string tokenString = authHeader.ToString();

            //2 Get rid of berarer prefix
            if(tokenString.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                tokenString = tokenString.Substring("Bearer ".Length).Trim();
            }
            else
            {
                context.Result = new Microsoft.AspNetCore.Mvc.UnauthorizedResult();
                return;
            }


            //3 Get configuration and security key
            var configuration = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var securityKey = configuration["SecurityKey"]??string.Empty;

            //4 verify the token
            if(!await Authenticator.VerifyTokenAsync(tokenString, securityKey))
            {
                context.Result = new Microsoft.AspNetCore.Mvc.UnauthorizedResult();
            }
            

        }
    }
}
