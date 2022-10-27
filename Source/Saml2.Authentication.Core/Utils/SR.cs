using System;
using System.Resources;

namespace dk.nita.saml20.Utils;

internal static  class SR
    {
               private static readonly bool s_usingResourceKeys = AppContext.TryGetSwitch("System.Resources.UseSystemResourceKeys", out bool usingResourceKeys) ? usingResourceKeys : false;

        // This method is used to decide if we need to append the exception message parameters to the message when calling SR.Format.
        // by default it returns the value of System.Resources.UseSystemResourceKeys AppContext switch or false if not specified.
        // Native code generators can replace the value this returns based on user input at the time of native code generation.
        // The Linker is also capable of replacing the value of this method when the application is being trimmed.
        private static bool UsingResourceKeys() => s_usingResourceKeys;

        internal static string GetResourceString(string resourceKey)
        {
            if (UsingResourceKeys())
            {
                return resourceKey;
            }

            string? resourceString = null;
            try
            {
                resourceString =
#if SYSTEM_PRIVATE_CORELIB || NATIVEAOT
                    InternalGetResourceString(resourceKey);
#else
                    ResourceManager.GetString(resourceKey);
#endif
            }
            catch (MissingManifestResourceException) { }

            return resourceString!; // only null if missing resources
        }

        internal static string GetResourceString(string resourceKey, string defaultString)
        {
            string resourceString = GetResourceString(resourceKey);

            return resourceKey == resourceString || resourceString == null ? defaultString : resourceString;
        }

        internal static string Format(string resourceFormat, object? p1)
        {
            if (UsingResourceKeys())
            {
                return string.Join(", ", resourceFormat, p1);
            }

            return string.Format(resourceFormat, p1);
        }

        internal static string Format(string resourceFormat, object? p1, object? p2)
        {
            if (UsingResourceKeys())
            {
                return string.Join(", ", resourceFormat, p1, p2);
            }

            return string.Format(resourceFormat, p1, p2);
        }

        internal static string Format(string resourceFormat, object? p1, object? p2, object? p3)
        {
            if (UsingResourceKeys())
            {
                return string.Join(", ", resourceFormat, p1, p2, p3);
            }

            return string.Format(resourceFormat, p1, p2, p3);
        }

        internal static string Format(string resourceFormat, params object?[]? args)
        {
            if (args != null)
            {
                if (UsingResourceKeys())
                {
                    return resourceFormat + ", " + string.Join(", ", args);
                }

                return string.Format(resourceFormat, args);
            }

            return resourceFormat;
        }

        internal static string Format(IFormatProvider? provider, string resourceFormat, object? p1)
        {
            if (UsingResourceKeys())
            {
                return string.Join(", ", resourceFormat, p1);
            }

            return string.Format(provider, resourceFormat, p1);
        }

        internal static string Format(IFormatProvider? provider, string resourceFormat, object? p1, object? p2)
        {
            if (UsingResourceKeys())
            {
                return string.Join(", ", resourceFormat, p1, p2);
            }

            return string.Format(provider, resourceFormat, p1, p2);
        }

        internal static string Format(IFormatProvider? provider, string resourceFormat, object? p1, object? p2, object? p3)
        {
            if (UsingResourceKeys())
            {
                return string.Join(", ", resourceFormat, p1, p2, p3);
            }

            return string.Format(provider, resourceFormat, p1, p2, p3);
        }

        internal static string Format(IFormatProvider? provider, string resourceFormat, params object?[]? args)
        {
            if (args != null)
            {
                if (UsingResourceKeys())
                {
                    return resourceFormat + ", " + string.Join(", ", args);
                }

                return string.Format(provider, resourceFormat, args);
            }

            return resourceFormat;
        }
        private static global::System.Resources.ResourceManager s_resourceManager;
        internal static global::System.Resources.ResourceManager ResourceManager => s_resourceManager ?? (s_resourceManager = new global::System.Resources.ResourceManager(typeof(SR)));

        /// <summary>Index was out of range. Must be non-negative and less than the size of the collection.</summary>
        internal static string @ArgumentOutOfRange_IndexMustBeLess => GetResourceString("ArgumentOutOfRange_IndexMustBeLess");
        /// <summary>Index was out of range. Must be non-negative and less than or equal to the size of the collection.</summary>
        internal static string @ArgumentOutOfRange_IndexMustBeLessOrEqual => GetResourceString("ArgumentOutOfRange_IndexMustBeLessOrEqual");
        /// <summary>String cannot be empty or null.</summary>
        internal static string @Arg_EmptyOrNullString => GetResourceString("Arg_EmptyOrNullString");
        /// <summary>A certificate chain could not be built to a trusted root authority.</summary>
        internal static string @Cryptography_Partial_Chain => GetResourceString("Cryptography_Partial_Chain");
        /// <summary>Bad wrapped key size.</summary>
        internal static string @Cryptography_Xml_BadWrappedKeySize => GetResourceString("Cryptography_Xml_BadWrappedKeySize");
        /// <summary>A Cipher Data element should have either a CipherValue or a CipherReference element.</summary>
        internal static string @Cryptography_Xml_CipherValueElementRequired => GetResourceString("Cryptography_Xml_CipherValueElementRequired");
        /// <summary>Could not create hash algorithm object.</summary>
        internal static string @Cryptography_Xml_CreateHashAlgorithmFailed => GetResourceString("Cryptography_Xml_CreateHashAlgorithmFailed");
        /// <summary>Could not create the XML transformation identified by the URI {0}.</summary>
        internal static string @Cryptography_Xml_CreateTransformFailed => GetResourceString("Cryptography_Xml_CreateTransformFailed");
        /// <summary>Failed to create signing key.</summary>
        internal static string @Cryptography_Xml_CreatedKeyFailed => GetResourceString("Cryptography_Xml_CreatedKeyFailed");
        /// <summary>A DigestMethod must be specified on a Reference prior to generating XML.</summary>
        internal static string @Cryptography_Xml_DigestMethodRequired => GetResourceString("Cryptography_Xml_DigestMethodRequired");
        /// <summary>A Reference must contain a DigestValue.</summary>
        internal static string @Cryptography_Xml_DigestValueRequired => GetResourceString("Cryptography_Xml_DigestValueRequired");
        /// <summary>An XmlDocument context is required for enveloped transforms.</summary>
        internal static string @Cryptography_Xml_EnvelopedSignatureRequiresContext => GetResourceString("Cryptography_Xml_EnvelopedSignatureRequiresContext");
        /// <summary>Malformed element {0}.</summary>
        internal static string @Cryptography_Xml_InvalidElement => GetResourceString("Cryptography_Xml_InvalidElement");
        /// <summary>Malformed encryption property element.</summary>
        internal static string @Cryptography_Xml_InvalidEncryptionProperty => GetResourceString("Cryptography_Xml_InvalidEncryptionProperty");
        /// <summary>The key size should be a non negative integer.</summary>
        internal static string @Cryptography_Xml_InvalidKeySize => GetResourceString("Cryptography_Xml_InvalidKeySize");
        /// <summary>Malformed reference element.</summary>
        internal static string @Cryptography_Xml_InvalidReference => GetResourceString("Cryptography_Xml_InvalidReference");
        /// <summary>The length of the signature with a MAC should be less than the hash output length.</summary>
        internal static string @Cryptography_Xml_InvalidSignatureLength => GetResourceString("Cryptography_Xml_InvalidSignatureLength");
        /// <summary>The length in bits of the signature with a MAC should be a multiple of 8.</summary>
        internal static string @Cryptography_Xml_InvalidSignatureLength2 => GetResourceString("Cryptography_Xml_InvalidSignatureLength2");
        /// <summary>X509 issuer serial number is invalid.</summary>
        internal static string @Cryptography_Xml_InvalidX509IssuerSerialNumber => GetResourceString("Cryptography_Xml_InvalidX509IssuerSerialNumber");
        /// <summary>A KeyInfo element is required to check the signature.</summary>
        internal static string @Cryptography_Xml_KeyInfoRequired => GetResourceString("Cryptography_Xml_KeyInfoRequired");
        /// <summary>The length of the encrypted data in Key Wrap is either 32, 40 or 48 bytes.</summary>
        internal static string @Cryptography_Xml_KW_BadKeySize => GetResourceString("Cryptography_Xml_KW_BadKeySize");
        /// <summary>Signing key is not loaded.</summary>
        internal static string @Cryptography_Xml_LoadKeyFailed => GetResourceString("Cryptography_Xml_LoadKeyFailed");
        /// <summary>Symmetric algorithm is not specified.</summary>
        internal static string @Cryptography_Xml_MissingAlgorithm => GetResourceString("Cryptography_Xml_MissingAlgorithm");
        /// <summary>Cipher data is not specified.</summary>
        internal static string @Cryptography_Xml_MissingCipherData => GetResourceString("Cryptography_Xml_MissingCipherData");
        /// <summary>Unable to retrieve the decryption key.</summary>
        internal static string @Cryptography_Xml_MissingDecryptionKey => GetResourceString("Cryptography_Xml_MissingDecryptionKey");
        /// <summary>Unable to retrieve the encryption key.</summary>
        internal static string @Cryptography_Xml_MissingEncryptionKey => GetResourceString("Cryptography_Xml_MissingEncryptionKey");
        /// <summary>The specified cryptographic transform is not supported.</summary>
        internal static string @Cryptography_Xml_NotSupportedCryptographicTransform => GetResourceString("Cryptography_Xml_NotSupportedCryptographicTransform");
        /// <summary>At least one Reference element is required.</summary>
        internal static string @Cryptography_Xml_ReferenceElementRequired => GetResourceString("Cryptography_Xml_ReferenceElementRequired");
        /// <summary>The Reference type must be set in an EncryptedReference object.</summary>
        internal static string @Cryptography_Xml_ReferenceTypeRequired => GetResourceString("Cryptography_Xml_ReferenceTypeRequired");
        /// <summary>An XmlDocument context is required to resolve the Reference Uri {0}.</summary>
        internal static string @Cryptography_Xml_SelfReferenceRequiresContext => GetResourceString("Cryptography_Xml_SelfReferenceRequiresContext");
        /// <summary>SignatureDescription could not be created for the signature algorithm supplied.</summary>
        internal static string @Cryptography_Xml_SignatureDescriptionNotCreated => GetResourceString("Cryptography_Xml_SignatureDescriptionNotCreated");
        /// <summary>The key does not fit the SignatureMethod.</summary>
        internal static string @Cryptography_Xml_SignatureMethodKeyMismatch => GetResourceString("Cryptography_Xml_SignatureMethodKeyMismatch");
        /// <summary>A signature method is required.</summary>
        internal static string @Cryptography_Xml_SignatureMethodRequired => GetResourceString("Cryptography_Xml_SignatureMethodRequired");
        /// <summary>Signature requires a SignatureValue.</summary>
        internal static string @Cryptography_Xml_SignatureValueRequired => GetResourceString("Cryptography_Xml_SignatureValueRequired");
        /// <summary>Signature requires a SignedInfo.</summary>
        internal static string @Cryptography_Xml_SignedInfoRequired => GetResourceString("Cryptography_Xml_SignedInfoRequired");
        /// <summary>The input type was invalid for this transform.</summary>
        internal static string @Cryptography_Xml_TransformIncorrectInputType => GetResourceString("Cryptography_Xml_TransformIncorrectInputType");
        /// <summary>Type of input object is invalid.</summary>
        internal static string @Cryptography_Xml_IncorrectObjectType => GetResourceString("Cryptography_Xml_IncorrectObjectType");
        /// <summary>Unknown transform has been encountered.</summary>
        internal static string @Cryptography_Xml_UnknownTransform => GetResourceString("Cryptography_Xml_UnknownTransform");
        /// <summary>Unable to resolve Uri {0}.</summary>
        internal static string @Cryptography_Xml_UriNotResolved => GetResourceString("Cryptography_Xml_UriNotResolved");
        /// <summary>The specified Uri is not supported.</summary>
        internal static string @Cryptography_Xml_UriNotSupported => GetResourceString("Cryptography_Xml_UriNotSupported");
        /// <summary>A Uri attribute is required for a CipherReference element.</summary>
        internal static string @Cryptography_Xml_UriRequired => GetResourceString("Cryptography_Xml_UriRequired");
        /// <summary>Null Context property encountered.</summary>
        internal static string @Cryptography_Xml_XrmlMissingContext => GetResourceString("Cryptography_Xml_XrmlMissingContext");
        /// <summary>IRelDecryptor is required.</summary>
        internal static string @Cryptography_Xml_XrmlMissingIRelDecryptor => GetResourceString("Cryptography_Xml_XrmlMissingIRelDecryptor");
        /// <summary>Issuer node is required.</summary>
        internal static string @Cryptography_Xml_XrmlMissingIssuer => GetResourceString("Cryptography_Xml_XrmlMissingIssuer");
        /// <summary>License node is required.</summary>
        internal static string @Cryptography_Xml_XrmlMissingLicence => GetResourceString("Cryptography_Xml_XrmlMissingLicence");
        /// <summary>Unable to decrypt grant content.</summary>
        internal static string @Cryptography_Xml_XrmlUnableToDecryptGrant => GetResourceString("Cryptography_Xml_XrmlUnableToDecryptGrant");
        /// <summary>The certificate key algorithm is not supported.</summary>
        internal static string @NotSupported_KeyAlgorithm => GetResourceString("NotSupported_KeyAlgorithm");
        /// <summary>Actual hash value: {0}</summary>
        internal static string @Log_ActualHashValue => GetResourceString("Log_ActualHashValue");
        /// <summary>Beginning canonicalization using "{0}" ({1}).</summary>
        internal static string @Log_BeginCanonicalization => GetResourceString("Log_BeginCanonicalization");
        /// <summary>Beginning signature computation.</summary>
        internal static string @Log_BeginSignatureComputation => GetResourceString("Log_BeginSignatureComputation");
        /// <summary>Beginning signature verification.</summary>
        internal static string @Log_BeginSignatureVerification => GetResourceString("Log_BeginSignatureVerification");
        /// <summary>Building and verifying the X509 chain for certificate {0}.</summary>
        internal static string @Log_BuildX509Chain => GetResourceString("Log_BuildX509Chain");
        /// <summary>Canonicalization transform is using resolver {0} and base URI "{1}".</summary>
        internal static string @Log_CanonicalizationSettings => GetResourceString("Log_CanonicalizationSettings");
        /// <summary>Output of canonicalization transform: {0}</summary>
        internal static string @Log_CanonicalizedOutput => GetResourceString("Log_CanonicalizedOutput");
        /// <summary>Certificate chain:</summary>
        internal static string @Log_CertificateChain => GetResourceString("Log_CertificateChain");
        /// <summary>Checking signature format using format validator "[{0}] {1}.{2}".</summary>
        internal static string @Log_CheckSignatureFormat => GetResourceString("Log_CheckSignatureFormat");
        /// <summary>Checking signature on SignedInfo with id "{0}".</summary>
        internal static string @Log_CheckSignedInfo => GetResourceString("Log_CheckSignedInfo");
        /// <summary>Signature format validation was successful.</summary>
        internal static string @Log_FormatValidationSuccessful => GetResourceString("Log_FormatValidationSuccessful");
        /// <summary>Signature format validation failed.</summary>
        internal static string @Log_FormatValidationNotSuccessful => GetResourceString("Log_FormatValidationNotSuccessful");
        /// <summary>Found key usages "{0}" in extension {1} on certificate {2}.</summary>
        internal static string @Log_KeyUsages => GetResourceString("Log_KeyUsages");
        /// <summary>No namespaces are being propagated.</summary>
        internal static string @Log_NoNamespacesPropagated => GetResourceString("Log_NoNamespacesPropagated");
        /// <summary>Propagating namespace {0}="{1}".</summary>
        internal static string @Log_PropagatingNamespace => GetResourceString("Log_PropagatingNamespace");
        /// <summary>Raw signature: {0}</summary>
        internal static string @Log_RawSignatureValue => GetResourceString("Log_RawSignatureValue");
        /// <summary>Reference {0} hashed with "{1}" ({2}) has hash value {3}, expected hash value {4}.</summary>
        internal static string @Log_ReferenceHash => GetResourceString("Log_ReferenceHash");
        /// <summary>Revocation mode for chain building: {0}.</summary>
        internal static string @Log_RevocationMode => GetResourceString("Log_RevocationMode");
        /// <summary>Revocation flag for chain building: {0}.</summary>
        internal static string @Log_RevocationFlag => GetResourceString("Log_RevocationFlag");
        /// <summary>Calculating signature with key {0} using signature description {1}, hash algorithm {2}, and asymmetric signature formatter {3}.</summary>
        internal static string @Log_SigningAsymmetric => GetResourceString("Log_SigningAsymmetric");
        /// <summary>Calculating signature using keyed hash algorithm {0}.</summary>
        internal static string @Log_SigningHmac => GetResourceString("Log_SigningHmac");
        /// <summary>Hashing reference {0}, Uri "{1}", Id "{2}", Type "{3}" with hash algorithm "{4}" ({5}).</summary>
        internal static string @Log_SigningReference => GetResourceString("Log_SigningReference");
        /// <summary>Transformed reference contents: {0}</summary>
        internal static string @Log_TransformedReferenceContents => GetResourceString("Log_TransformedReferenceContents");
        /// <summary>Canonicalization method "{0}" is not on the safe list. Safe canonicalization methods are: {1}.</summary>
        internal static string @Log_UnsafeCanonicalizationMethod => GetResourceString("Log_UnsafeCanonicalizationMethod");
        /// <summary>URL retrieval timeout for chain building: {0}.</summary>
        internal static string @Log_UrlTimeout => GetResourceString("Log_UrlTimeout");
        /// <summary>Verification failed checking {0}.</summary>
        internal static string @Log_VerificationFailed => GetResourceString("Log_VerificationFailed");
        /// <summary>references</summary>
        internal static string @Log_VerificationFailed_References => GetResourceString("Log_VerificationFailed_References");
        /// <summary>SignedInfo</summary>
        internal static string @Log_VerificationFailed_SignedInfo => GetResourceString("Log_VerificationFailed_SignedInfo");
        /// <summary>X509 chain verification</summary>
        internal static string @Log_VerificationFailed_X509Chain => GetResourceString("Log_VerificationFailed_X509Chain");
        /// <summary>X509 key usage verification</summary>
        internal static string @Log_VerificationFailed_X509KeyUsage => GetResourceString("Log_VerificationFailed_X509KeyUsage");
        /// <summary>Verification flags for chain building: {0}.</summary>
        internal static string @Log_VerificationFlag => GetResourceString("Log_VerificationFlag");
        /// <summary>Verification time for chain building: {0}.</summary>
        internal static string @Log_VerificationTime => GetResourceString("Log_VerificationTime");
        /// <summary>Verification with key {0} was successful.</summary>
        internal static string @Log_VerificationWithKeySuccessful => GetResourceString("Log_VerificationWithKeySuccessful");
        /// <summary>Verification with key {0} was not successful.</summary>
        internal static string @Log_VerificationWithKeyNotSuccessful => GetResourceString("Log_VerificationWithKeyNotSuccessful");
        /// <summary>Processing reference {0}, Uri "{1}", Id "{2}", Type "{3}".</summary>
        internal static string @Log_VerifyReference => GetResourceString("Log_VerifyReference");
        /// <summary>Verifying SignedInfo using key {0}, signature description {1}, hash algorithm {2}, and asymmetric signature deformatter {3}.</summary>
        internal static string @Log_VerifySignedInfoAsymmetric => GetResourceString("Log_VerifySignedInfoAsymmetric");
        /// <summary>Verifying SignedInfo using keyed hash algorithm {0}.</summary>
        internal static string @Log_VerifySignedInfoHmac => GetResourceString("Log_VerifySignedInfoHmac");
        /// <summary>Error building X509 chain: {0}: {1}.</summary>
        internal static string @Log_X509ChainError => GetResourceString("Log_X509ChainError");
        /// <summary>Using context: {0}</summary>
        internal static string @Log_XmlContext => GetResourceString("Log_XmlContext");
        /// <summary>Signed xml recursion limit hit while trying to decrypt the key. Reference {0} hashed with "{1}" and ({2}).</summary>
        internal static string @Log_SignedXmlRecursionLimit => GetResourceString("Log_SignedXmlRecursionLimit");
        /// <summary>Transform method "{0}" is not on the safe list. Safe transform methods are: {1}.</summary>
        internal static string @Log_UnsafeTransformMethod => GetResourceString("Log_UnsafeTransformMethod");
        /// <summary>{0} and {1} can only occur in combination</summary>
        internal static string @ElementCombinationMissing => GetResourceString("ElementCombinationMissing");
        /// <summary>{0} is missing</summary>
        internal static string @ElementMissing => GetResourceString("ElementMissing");
        /// <summary>{0} must contain child element {1}</summary>
        internal static string @MustContainChildElement => GetResourceString("MustContainChildElement");
        /// <summary>Root element must be {0} element in namespace {1}</summary>
        internal static string @WrongRootElement => GetResourceString("WrongRootElement");
        /// <summary>External entity resolution is not supported.</summary>
        internal static string @Cryptography_Xml_EntityResolutionNotSupported => GetResourceString("Cryptography_Xml_EntityResolutionNotSupported");

    }