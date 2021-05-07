using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JwtGenerator2
{
    class Program
    {
        static void Main(string[] args)
        {
            var token = GenerateToken();
            ValidateToken(token);
        }

        private static string GenerateToken()
        {
            const string sec = "ProEMLh5e_qnzdNUQrqdHPgp";
            const string sec1 = "ProEMLh5e_qnzdNU";
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(sec));
            var securityKey1 = new SymmetricSecurityKey(Encoding.Default.GetBytes(sec1));

            var signingCredentials = new SigningCredentials(
                securityKey,
                SecurityAlgorithms.HmacSha512);

            List<Claim> claims = new List<Claim>()
                {
                    new Claim("sub", "test"),
                    new Claim("TokenGuid", Guid.NewGuid().ToString()),
                };

            var ep = new EncryptingCredentials(
                securityKey1,
                SecurityAlgorithms.Aes128KW,
                SecurityAlgorithms.Aes128CbcHmacSha256);

            var handler = new JwtSecurityTokenHandler();

            //var jwtSecurityToken = handler.CreateJwtSecurityToken(
            //    "issuer",
            //    "Audience",
            //    new ClaimsIdentity(claims),
            //    DateTime.Now,
            //    DateTime.Now.AddHours(1),
            //    DateTime.Now,
            //    signingCredentials,
            //    ep);

            var jwtSecurityToken = handler.CreateJwtSecurityToken(
               "issuer",
               "Audience",
               new ClaimsIdentity(claims),
               DateTime.Now,
               DateTime.Now.AddHours(2),
               DateTime.Now,
               signingCredentials);

            var secToken = new JwtSecurityToken(
           signingCredentials: signingCredentials,
           issuer: "Sample",
           audience: "Sample",
           claims: new[]
           {
                new Claim(JwtRegisteredClaimNames.Sub, "meziantou")
           },
           expires: DateTime.UtcNow.AddSeconds(1)
           );


            string tokenString = handler.WriteToken(jwtSecurityToken);

            // Id someone tries to view the JWT without validating/decrypting the token,
            // then no claims are retrieved and the token is safe guarded.
            var jwt = new JwtSecurityToken(tokenString);
           
            return tokenString;
        }

        private static void ValidateToken(string _token)
        {
            _token = Res1.token1;
            const string sec = "ProEMLh5e_qnzdNUQrqdHPgp";
            const string sec1 = "ProEMLh5e_qnzdNU";
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(sec));
            var securityKey1 = new SymmetricSecurityKey(Encoding.Default.GetBytes(sec1));
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(sec)),
                //TokenDecryptionKeys =new List<SymmetricSecurityKey>() { securityKey1 },
                ValidateLifetime = true, // Because there is no expiration in the generated token
                ValidateAudience = false, // Because there is no audiance in the generated token
                ValidateIssuer = false,
                RequireExpirationTime=true,
                ClockSkew = TimeSpan.Zero
            };

            try
            {
                SecurityToken validatedToken;
                var principal = handler.ValidateToken(_token, validationParameters, out validatedToken);
            }
            catch (Exception e)
            {
                Console.WriteLine("{0}\n {1}", e.Message, e.StackTrace);
            }

            Console.WriteLine();
        }
    }
}
