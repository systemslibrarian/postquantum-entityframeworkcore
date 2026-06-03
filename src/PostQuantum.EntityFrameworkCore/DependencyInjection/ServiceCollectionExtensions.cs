using Microsoft.Extensions.DependencyInjection;
using PostQuantum.EntityFrameworkCore.Crypto;

namespace PostQuantum.EntityFrameworkCore.DependencyInjection;

/// <summary>
/// Registers PostQuantum.EntityFrameworkCore services in a dependency-injection container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds an <see cref="IPostQuantumProtector"/> configured by <paramref name="configure"/>.
    /// </summary>
    /// <example>
    /// <code>
    /// services.AddPostQuantumEncryption(pq =&gt;
    /// {
    ///     pq.UseAes256Gcm(keyRing);
    /// });
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">No scheme was configured.</exception>
    public static IServiceCollection AddPostQuantumEncryption(
        this IServiceCollection services,
        Action<PostQuantumEncryptionBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new PostQuantumEncryptionBuilder(services);
        configure(builder);
        EncryptionScheme defaultScheme = builder.ResolveDefaultScheme();

        services.AddSingleton<IPostQuantumProtector>(sp =>
            new PostQuantumProtector(sp.GetServices<IEncryptionSchemeHandler>(), defaultScheme));

        return services;
    }
}
