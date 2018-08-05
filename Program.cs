using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace JwtConfiguration
{
    class Program
    {
        
        static void Main(string[] args)
        {
            // this is a list of user information that we will use to create claims
            var name = "John Doe";
            var userId = 1;
            var userRole = "Marketer";

            string tokenString = BuildJsonWebToken(name, userId, userRole);
            const string fakeToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoiSm9obiBEb2UiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6IjEiLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOiJuIiwiZXhwIjoxNTMzNDE1MDIxLCJpc3MiOiJCaWcgQ29tcGFueSwgSW5jIiwiYXVkIjoiQmlnIENvbXBhbnksIEluYyBFbXBsb3llZXMifQ.SPNYNoH0FHe-s3lcRLDdPDLyC4MQF_Kih1HwVWAcGWg";

            Console.WriteLine(tokenString);

            try
            {
                // get the ClaimsPrincipal object from our custom method
                ClaimsPrincipal claimsPrincipal = ValidateJsonWebToken(tokenString);
                // iterate through the list of claims that lives on the ClaimsPrincipals object
                System.Console.WriteLine("Token Claims information for: " + claimsPrincipal.Identity.Name);
                foreach(var claim in claimsPrincipal.Claims)
                    System.Console.WriteLine("CLAIM " + claim.Type.ToString() + ": " + claim.Value.ToString());
            }
            catch (SecurityTokenInvalidSignatureException e)
            {
                System.Console.WriteLine("Could not validate token signature for JWS");
                System.Console.WriteLine(e.Message);
            }
            catch (Exception e)
            {
                System.Console.WriteLine(e.Message);
            }
        }

        public static ClaimsPrincipal ValidateJsonWebToken(string jwt)
        {
            // this is an object that will validate the token parameter of this method
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            // this is an object that will be filled with the result of the validated token from the ValidateToken method
            SecurityToken validatedToken = new JwtSecurityToken();

            try
            {
                ClaimsPrincipal claims = handler.ValidateToken(jwt, JwtValidator.tokenValidationParameters, out validatedToken);
                System.Console.WriteLine("Token was validated!");
                return claims;
            }
            catch (SecurityTokenInvalidSignatureException e)
            {
                throw e;
            }
        }

        public static string BuildJsonWebToken(string name, int userId, string userRole)
        {
            // this symmetric security key creates inherits from sercurity key and takes in a byte array
            // we must convert the private key that was on our server into a security key by using the ASCII GetBytes method
            // to retreive the bytes array of the secret string
            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(System.Text.Encoding.ASCII.GetBytes(JwtValidator.secret));

            // create the signature of the token that will be used to hash the secret
            // using the security key we created above and a security hashing algorithm method used to hash the key
            SigningCredentials signature = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // this is a list of claims to which we will add to the part 2 (the payload) of the JSON Web Token
            IEnumerable<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, name), // shows the users name in the claim
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()), // shows the user's unique identifier
                new Claim(ClaimTypes.Role, userRole) // shows the users role within the claim (used for authorization)
            };


            // this is where we are building the actual JSON Web Token to return as a string
            // we are including everything we would like to have in the payload
            // we also including the jwt signature (that we hashed using SHA256 above) to make this a JWS
            SecurityToken token = new JwtSecurityToken
            (
                issuer: JwtValidator.issuer,
                audience: JwtValidator.audience,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddMinutes(60),
                claims: claims,
                signingCredentials: signature
            );

            // this class comes from the System.IdentityModel.Tokens.Jwt and can validate and serialize tokens
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            // we will be using it to serialize the JwtSecurityToken above into a string to return
            string tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }
    }
}
