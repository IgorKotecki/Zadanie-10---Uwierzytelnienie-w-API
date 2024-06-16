using System.Security.Cryptography;
using System.Text;

namespace WebApplication2.Helper;

public static class SecurityHelpers
{
    public static (string, string) GetHashedPasswordAndSalt(string password)
    {
        var salt = GenerateSalt();
        var hashedPassword = GetHashedPasswordWithSalt(password, salt);
        return (hashedPassword, salt);
    }

    public static string GetHashedPasswordWithSalt(string password, string salt)
    {
        using (var sha256 = SHA256.Create())
        {
            var saltedPassword = password + salt;
            var saltedPasswordBytes = Encoding.UTF8.GetBytes(saltedPassword);
            var hashedBytes = sha256.ComputeHash(saltedPasswordBytes);
            return Convert.ToBase64String(hashedBytes);
        }
    }

    public static string GenerateSalt()
    {
        var randomBytes = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        return Convert.ToBase64String(randomBytes);
    }

    public static string GenerateRefreshToken()
    {
        var randomBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        return Convert.ToBase64String(randomBytes);
    }
}