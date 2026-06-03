using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.Keys;

namespace PostQuantum.EntityFrameworkCore.DependencyInjection;

/// <summary>
/// Configures the encryption schemes and key rings used by
/// <see cref="IPostQuantumProtector"/>. Obtained from
/// <see cref="ServiceCollectionExtensions.AddPostQuantumEncryption"/>.
/// </summary>
/// <remarks>
/// The first scheme registered becomes the default for new writes unless a later call
/// passes <c>asDefault: true</c>. Registering additional schemes lets the protector
/// decrypt values written under a previous scheme — useful during a migration from
/// AES-only to the post-quantum envelope.
/// </remarks>
public sealed class PostQuantumEncryptionBuilder
{
    private readonly IServiceCollection _services;

    internal PostQuantumEncryptionBuilder(IServiceCollection services)
    {
        _services = services;
    }

    /// <summary>The scheme that will encrypt new values. Set by the scheme registrations below.</summary>
    internal EncryptionScheme? DefaultScheme { get; private set; }

    /// <summary>The service collection being configured.</summary>
    public IServiceCollection Services => _services;

    /// <summary>
    /// Registers the AES-256-GCM scheme using the supplied data-protection key ring.
    /// </summary>
    public PostQuantumEncryptionBuilder UseAes256Gcm(IDataProtectionKeyRing keyRing, bool asDefault = true)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        return UseAes256Gcm(_ => keyRing, asDefault);
    }

    /// <summary>
    /// Registers the AES-256-GCM scheme using a factory that resolves the key ring from DI
    /// (for example, an adapter over <c>PostQuantum.KeyManagement</c>).
    /// </summary>
    public PostQuantumEncryptionBuilder UseAes256Gcm(
        Func<IServiceProvider, IDataProtectionKeyRing> keyRingFactory,
        bool asDefault = true)
    {
        ArgumentNullException.ThrowIfNull(keyRingFactory);
        _services.AddSingleton<IEncryptionSchemeHandler>(sp => new Aes256GcmSchemeHandler(keyRingFactory(sp)));
        SetDefault(EncryptionScheme.Aes256Gcm, asDefault);
        return this;
    }

    /// <summary>
    /// Registers the ML-KEM-768 hybrid envelope scheme using the supplied key-encapsulation
    /// key ring. Requires a platform with ML-KEM support at run time (see
    /// <see cref="MLKemKeyEncapsulationMechanism"/>).
    /// </summary>
    public PostQuantumEncryptionBuilder UseMLKem768Envelope(IKeyEncapsulationKeyRing keyRing, bool asDefault = true)
    {
        ArgumentNullException.ThrowIfNull(keyRing);
        return UseMLKem768Envelope(_ => keyRing, asDefault);
    }

    /// <summary>
    /// Registers the ML-KEM-768 hybrid envelope scheme using a factory that resolves the key
    /// ring from DI.
    /// </summary>
    public PostQuantumEncryptionBuilder UseMLKem768Envelope(
        Func<IServiceProvider, IKeyEncapsulationKeyRing> keyRingFactory,
        bool asDefault = true)
    {
        ArgumentNullException.ThrowIfNull(keyRingFactory);
        _services.TryAddSingleton<IKeyEncapsulationMechanism, MLKemKeyEncapsulationMechanism>();
        _services.AddSingleton<IEncryptionSchemeHandler>(sp => new MLKemEnvelopeSchemeHandler(
            keyRingFactory(sp),
            sp.GetRequiredService<IKeyEncapsulationMechanism>()));
        SetDefault(EncryptionScheme.MLKem768Aes256Gcm, asDefault);
        return this;
    }

    /// <summary>
    /// Registers a custom <see cref="IKeyEncapsulationMechanism"/> (for example, a
    /// hardware-backed KEM or a test double) before configuring the envelope scheme.
    /// </summary>
    public PostQuantumEncryptionBuilder UseKeyEncapsulationMechanism(IKeyEncapsulationMechanism mechanism)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        _services.AddSingleton(mechanism);
        return this;
    }

    internal EncryptionScheme ResolveDefaultScheme() =>
        DefaultScheme ?? throw new InvalidOperationException(
            "No encryption scheme was configured. Call UseAes256Gcm(...) or UseMLKem768Envelope(...).");

    private void SetDefault(EncryptionScheme scheme, bool asDefault)
    {
        if (asDefault || DefaultScheme is null)
        {
            DefaultScheme = scheme;
        }
    }
}
