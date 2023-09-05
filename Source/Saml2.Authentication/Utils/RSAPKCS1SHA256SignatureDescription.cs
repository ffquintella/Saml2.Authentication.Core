using System.Security.Cryptography;

namespace dk.nita.saml20.Utils;

internal sealed class RSAPKCS1SHA256SignatureDescription : RSAPKCS1SignatureDescription
{
    public RSAPKCS1SHA256SignatureDescription() : base("SHA256")
    {
    }

    public sealed override HashAlgorithm CreateDigest()
    {
        return SHA256.Create();
    }
}