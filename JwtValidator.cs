using Microsoft.IdentityModel.Tokens;

namespace JwtConfiguration
{
    public class JwtValidator
    {
        // secret string that is stored on the server used to validate authenticity of the JWT
        public static string secret = "asldkfjjwoiwjeoijiojwf5640654065406540dfsdf6s5d40f6s5d4f0s65df40s6d5f40s6d54f0";
        // issuer of the JWT (put into the payload)
        public static string issuer = "Big Company, Inc";
        // audience of the JWT (put into the payload)
        public static string audience = "Big Company, Inc Employees";
        // validation parameters for the server so that the server understands how to validate a token coming in
        public static TokenValidationParameters tokenValidationParameters = new TokenValidationParameters()
        {
            IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.ASCII.GetBytes(secret)),
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidAudience = audience,
            ValidIssuer = issuer,
            ValidateIssuerSigningKey = true,
            RequireExpirationTime = true
        };
    }
}