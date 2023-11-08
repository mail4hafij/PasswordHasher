# PasswordHasher
A simple C# class to hash a password.

```
public class PasswordHasher : IPasswordHasher
{
    private const int _saltSize = 128 / 8;
    private const int _keySize = 256 / 8;
    private const int _iteration = 1000;
    private const char _delemeter = ';';
    
    public string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(_saltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, _iteration, HashAlgorithmName.SHA256, _keySize);

        return string.Join(_delemeter, Convert.ToBase64String(salt), Convert.ToBase64String(hash));
    }

    public bool Verify(string password, string hashedPassword)
    {
        var originalSaltAndHash = hashedPassword.Split(_delemeter);
        var originalSalt = Convert.FromBase64String(originalSaltAndHash[0]);
        var originalHash = Convert.FromBase64String(originalSaltAndHash[1]);

        var hash = Rfc2898DeriveBytes.Pbkdf2(password, originalSalt, _iteration, HashAlgorithmName.SHA256, _keySize);
        return CryptographicOperations.FixedTimeEquals(originalHash, hash);
    }
}

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string hashedPassword);
}

```

Enjoy!
