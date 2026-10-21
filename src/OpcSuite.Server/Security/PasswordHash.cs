using System.Globalization;
using System.Security.Cryptography;

namespace OpcSuite.Server.Security;

/// <summary>
/// Salted PBKDF2-HMAC-SHA256 password hashes, stored as <c>pbkdf2-sha256$iterations$salt$hash</c> (base64).
/// The iteration count follows the OWASP recommendation for PBKDF2-HMAC-SHA256 and is stored with every hash,
/// so it can be raised later without invalidating existing passwords.
/// </summary>
public static class PasswordHash
{
    public const int DefaultIterations = 600_000;
    private const string Scheme = "pbkdf2-sha256";
    private const int SaltSize = 16;
    private const int HashSize = 32;

    public static string Create(ReadOnlySpan<char> password, int iterations = DefaultIterations)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        // the char overload hashes the UTF-8 bytes, which is what a client sends in its user name token
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, HashSize);
        return string.Join('$', Scheme, iterations.ToString(CultureInfo.InvariantCulture), Convert.ToBase64String(salt), Convert.ToBase64String(hash));
    }

    /// <summary>Checks a UTF-8 encoded password in constant time. A malformed hash never matches.</summary>
    public static bool Verify(ReadOnlySpan<byte> passwordUtf8, string storedHash)
    {
        if (!TryDecode(storedHash, out var iterations, out var salt, out var expected))
        {
            return false;
        }
        var actual = Rfc2898DeriveBytes.Pbkdf2(passwordUtf8, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public static bool IsWellFormed(string storedHash) => TryDecode(storedHash, out _, out _, out _);

    private static bool TryDecode(string storedHash, out int iterations, out byte[] salt, out byte[] hash)
    {
        iterations = 0;
        salt = hash = [];
        if (storedHash.Split('$') is not [Scheme, var iterationText, var saltText, var hashText]
            || !int.TryParse(iterationText, NumberStyles.None, CultureInfo.InvariantCulture, out iterations)
            || iterations < 1)
        {
            return false;
        }
        try
        {
            salt = Convert.FromBase64String(saltText);
            hash = Convert.FromBase64String(hashText);
        }
        catch (FormatException)
        {
            return false;
        }
        return salt.Length >= SaltSize && hash.Length >= HashSize;
    }
}
