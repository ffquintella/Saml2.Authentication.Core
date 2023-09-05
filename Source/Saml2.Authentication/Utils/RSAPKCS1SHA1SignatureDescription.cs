using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace dk.nita.saml20.Utils;


internal sealed class RSAPKCS1SHA1SignatureDescription : RSAPKCS1SignatureDescription
{
    public RSAPKCS1SHA1SignatureDescription() : base("SHA1")
    {
    }

    [SuppressMessage("Microsoft.Security", "CA5350", Justification = "SHA1 needed for compat.")]
    public sealed override HashAlgorithm CreateDigest()
    {
        return SHA1.Create();
    }
}
