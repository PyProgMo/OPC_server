using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpcSuite.Crypto;

namespace OpcSuite.Client;

/// <summary>
/// Certificates that identify a user rather than the application. The key pair is made here and the private key
/// never leaves this machine; the server operator only registers the certificate's SHA-256 fingerprint for a user.
/// Each one is kept as <c>&lt;name&gt;.pfx</c> (with the private key, not password protected - like the application's
/// own key, it is protected by the folder's permissions) and <c>&lt;name&gt;.der</c> (public part, for the operator).
/// </summary>
public static class UserCertificates
{
    public static string DirectoryOf(PkiLayout pki) => Path.Combine(pki.Root, "user");

    public static X509Certificate2 Create(string directory, string name, TimeSpan validity)
    {
        ValidateName(name);
        var pfx = Path.Combine(directory, name + ".pfx");
        if (File.Exists(pfx))
        {
            throw new InvalidOperationException($"A user certificate named '{name}' already exists: {pfx}");
        }

        using var key = RSA.Create(2048);
        var subject = new X500DistinguishedNameBuilder();
        subject.AddCommonName(name);
        subject.AddOrganizationName("OpcSuite");
        var request = new CertificateRequest(subject.Build(), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2", "Client Authentication")], false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var now = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(now.AddMinutes(-5), now.Add(validity));

        Directory.CreateDirectory(directory);
        WritePrivate(pfx, certificate.Export(X509ContentType.Pkcs12));
        File.WriteAllBytes(Path.Combine(directory, name + ".der"), certificate.Export(X509ContentType.Cert));
        return Load(directory, name);
    }

    /// <summary>Loads a user certificate with its private key, by the name it was created with or from a .pfx file.</summary>
    public static X509Certificate2 Load(string directory, string nameOrFile)
    {
        var file = File.Exists(nameOrFile) ? nameOrFile : Path.Combine(directory, nameOrFile + ".pfx");
        if (!File.Exists(file))
        {
            throw new FileNotFoundException(
                $"No user certificate '{nameOrFile}' (looked for {file}). Create one with 'opcctl user-cert create {nameOrFile}' or give a .pfx file.");
        }
        // keep the key in memory only; macOS has no ephemeral key sets and uses a temporary keychain instead
        var flags = OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(file, password: null, flags);
        if (!certificate.HasPrivateKey)
        {
            certificate.Dispose();
            throw new InvalidOperationException($"{file} contains no private key, so it cannot be used to log in.");
        }
        return certificate;
    }

    public static IReadOnlyList<(string Name, CertificateSummary Certificate)> List(string directory) =>
        Directory.Exists(directory)
            ? Directory.EnumerateFiles(directory, "*.der")
                .Order(StringComparer.Ordinal)
                .Select(f => (Path.GetFileNameWithoutExtension(f), CertificateSummary.From(X509CertificateLoader.LoadCertificateFromFile(f))))
                .ToList()
            : [];

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 64 || !name.All(c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-' or '@'))
        {
            throw new ArgumentException($"'{name}' is not a valid name: use 1 to 64 letters, digits and . _ - @");
        }
    }

    private static void WritePrivate(string file, byte[] content)
    {
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllBytes(file, content);
            return;
        }
        // created readable for the owner only, before the key is in it
        using var stream = new FileStream(file, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
        stream.Write(content);
    }
}
