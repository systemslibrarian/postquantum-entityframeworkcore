using Microsoft.Extensions.DependencyInjection;
using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.DependencyInjection;
using PostQuantum.EntityFrameworkCore.Keys;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

public class DependencyInjectionTests
{
    [Fact]
    public void AddPostQuantumEncryption_with_aes_resolves_a_working_protector()
    {
        using DataEncryptionKey dek = DataEncryptionKey.Generate("dek-di");
        var services = new ServiceCollection();
        services.AddPostQuantumEncryption(pq => pq.UseAes256Gcm(new InMemoryDataProtectionKeyRing(dek)));

        using ServiceProvider provider = services.BuildServiceProvider();
        var protector = provider.GetRequiredService<IPostQuantumProtector>();

        Assert.Equal(EncryptionScheme.Aes256Gcm, protector.DefaultScheme);
        Assert.Equal("hello", protector.UnprotectText(protector.ProtectText("hello")));
    }

    [Fact]
    public void AddPostQuantumEncryption_registers_the_protector_as_a_singleton()
    {
        using DataEncryptionKey dek = DataEncryptionKey.Generate("dek-di");
        var services = new ServiceCollection();
        services.AddPostQuantumEncryption(pq => pq.UseAes256Gcm(new InMemoryDataProtectionKeyRing(dek)));

        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.Same(
            provider.GetRequiredService<IPostQuantumProtector>(),
            provider.GetRequiredService<IPostQuantumProtector>());
    }

    [Fact]
    public void AddPostQuantumEncryption_envelope_default_with_aes_fallback_chooses_envelope()
    {
        using DataEncryptionKey dek = DataEncryptionKey.Generate("dek-di");
        var kem = new FakeKeyEncapsulationMechanism();
        KeyEncapsulationKeyPair kek = kem.GenerateKeyPair("kek-di");

        var services = new ServiceCollection();
        services.AddPostQuantumEncryption(pq =>
        {
            pq.UseKeyEncapsulationMechanism(kem);
            pq.UseAes256Gcm(new InMemoryDataProtectionKeyRing(dek), asDefault: false);
            pq.UseMLKem768Envelope(new InMemoryKeyEncapsulationKeyRing(kek));
        });

        using ServiceProvider provider = services.BuildServiceProvider();
        var protector = provider.GetRequiredService<IPostQuantumProtector>();

        Assert.Equal(EncryptionScheme.MLKem768Aes256Gcm, protector.DefaultScheme);
        Assert.Equal("x", protector.UnprotectText(protector.ProtectText("x")));
    }

    [Fact]
    public void AddPostQuantumEncryption_throws_when_no_scheme_is_configured()
    {
        var services = new ServiceCollection();

        Assert.Throws<InvalidOperationException>(
            () => services.AddPostQuantumEncryption(_ => { }));
    }
}
