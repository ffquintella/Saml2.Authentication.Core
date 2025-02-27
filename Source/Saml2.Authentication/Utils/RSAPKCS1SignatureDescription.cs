using System.Security.Cryptography;

namespace dk.nita.saml20.Utils;

internal abstract class RSAPKCS1SignatureDescription : SignatureDescription
{
    public RSAPKCS1SignatureDescription(string hashAlgorithmName)
    {
        KeyAlgorithm = typeof(RSA).AssemblyQualifiedName;
        FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).AssemblyQualifiedName;
        DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).AssemblyQualifiedName;
        DigestAlgorithm = hashAlgorithmName;
    }

    public sealed override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
    {
        var item = (AsymmetricSignatureDeformatter)CryptoConfig.CreateFromName(DeformatterAlgorithm);
        item.SetKey(key);
        item.SetHashAlgorithm(DigestAlgorithm);
        return item;
    }

    public sealed override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
        var item = (AsymmetricSignatureFormatter)CryptoConfig.CreateFromName(FormatterAlgorithm);
        item.SetKey(key);
        item.SetHashAlgorithm(DigestAlgorithm);
        return item;
    }

    public abstract override HashAlgorithm CreateDigest();
}