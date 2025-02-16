using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace JWTAuthentication.Handler {
    public class JwtMiddleware {
        private readonly RequestDelegate _next;
        private readonly ILogger<JwtMiddleware> _logger;

        public JwtMiddleware(RequestDelegate next, ILogger<JwtMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (context.Request.Path == "/api/Login") {
                // Proceed to the next middleware if the token is valid
                await _next(context);
            }

            if (token != null) {
                try {
                    var MyConfig = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build();
                    var jwtKey = MyConfig.GetValue<string>("Jwt:Key");
                    var Issuer = MyConfig.GetValue<string>("Jwt:Issuer");
                    var Audience = MyConfig.GetValue<string>("Jwt:Audience");

                    //var AppName = MyConfig.GetValue<string>("AppSettings:APP_Name");

                    // Validate the token manually here or use the default JWT handler
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var key = Encoding.ASCII.GetBytes(jwtKey); // Secret used to validate token
                    var tokenValidationParameters = new TokenValidationParameters {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = Issuer,
                        ValidAudience = Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(key)
                    };

                    // Perform the validation
                    var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);

                    // If valid, add user claims to context (optional)
                    context.User = principal;
                }
                catch (Exception ex) {
                    _logger.LogError($"Error validating token: {ex.Message}");
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Invalid token or expired");
                    return;
                }
            } else {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Invalid token or expired");
                return;
            }

            // Proceed to the next middleware if the token is valid
            await _next(context);
        }
    }

}
