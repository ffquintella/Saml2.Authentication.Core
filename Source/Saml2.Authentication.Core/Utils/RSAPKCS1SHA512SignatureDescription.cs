using System.Security.Cryptography;

namespace dk.nita.saml20.Utils;

internal sealed class RSAPKCS1SHA512SignatureDescription : RSAPKCS1SignatureDescription
{
    public RSAPKCS1SHA512SignatureDescription() : base("SHA512")
    {
    }

    public sealed override HashAlgorithm CreateDigest()
    {
        return SHA512.Create();
    }
}