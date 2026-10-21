using OpcSuite.Core.Modules;
using OpcSuite.Crypto;
using OpcSuite.Modules.Demo;
using Xunit;

namespace OpcSuite.Tests;

public sealed class UnitTests
{
    [Theory]
    [InlineData("Basic256Sha256", true)]
    [InlineData("aes256_sha256_rsapss", true)]
    [InlineData("None", false)]
    [InlineData("Basic128Rsa15", false)]
    public void Only_sha256_encrypting_profiles_can_be_selected(string name, bool expected)
    {
        Assert.Equal(expected, SecurityProfile.TryParse(name, out var profile));
        if (expected)
        {
            Assert.Equal(Opc.Ua.MessageSecurityMode.SignAndEncrypt, profile.Mode);
        }
    }

    [Fact]
    public void Fingerprints_are_normalised_for_pasting()
    {
        Assert.Equal("ABCD01", Fingerprint.Normalize("ab:cd:01"));
        Assert.Equal("AB:CD:01", Fingerprint.Format("ABCD01"));
    }

    [Fact]
    public void Duplicate_module_names_are_rejected()
    {
        var catalog = new ModuleCatalog().Add<DemoModule>();

        Assert.Throws<InvalidOperationException>(() => catalog.Add<DemoModule>());
    }
}
