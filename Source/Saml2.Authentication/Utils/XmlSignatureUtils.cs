using System.Reflection;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Serilog;

namespace dk.nita.saml20.Utils
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Cryptography.Xml;
    using System.Xml;
    using Signature = Schema.XmlDSig.Signature;

   public class SignedXMLWithIdResolvement : SignedXml
    {
        public SignedXMLWithIdResolvement(XmlDocument document)
            : base(document)
        {
        }

      public SignedXMLWithIdResolvement(XmlElement elem)
            : base(elem)
        {
        }

       public SignedXMLWithIdResolvement()
        {
        }

        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            XmlElement elem;
            if ((elem = base.GetIdElement(document, idValue)) == null)
            {
                var nl = document.GetElementsByTagName("*");
                var enumerator = nl.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    var node = (XmlNode)enumerator.Current;
                    var nodeEnum = node.Attributes.GetEnumerator();
                    while (nodeEnum.MoveNext())
                    {
                        var attr = (XmlAttribute) nodeEnum.Current;
                        if (attr.LocalName.ToLower() == "id" && attr.Value == idValue && node is XmlElement)
                        {
                            return (XmlElement)node;
                        }
                    }
                }
            }

            return elem;
        }
    }

    /// <summary>
    ///     This class contains methods that creates and validates signatures on XmlDocuments.
    /// </summary>
    public class XmlSignatureUtils
    {
        /// <summary>
        ///     Verifies the signature of the XmlDocument instance using the key enclosed with the signature.
        /// </summary>
        /// <returns>
        ///     <code>true</code> if the document's signature can be verified. <code>false</code> if the signature could
        ///     not be verified.
        /// </returns>
        /// <exception cref="InvalidOperationException">if the XmlDocument instance does not contain a signed XML document.</exception>
        public static bool CheckSignature(XmlDocument doc)
        {
            CheckDocument(doc);
            var signedXml = RetrieveSignature(doc);

            var lCert = GetCertificates(doc);
            if (CheckSignature(signedXml, lCert))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        ///     Verifies the signature of the XmlDocument instance using the key given as a parameter.
        /// </summary>
        /// <returns>
        ///     <code>true</code> if the document's signature can be verified. <code>false</code> if the signature could
        ///     not be verified.
        /// </returns>
        /// <exception cref="InvalidOperationException">if the XmlDocument instance does not contain a signed XML document.</exception>
        public static bool CheckSignature(XmlDocument doc, AsymmetricAlgorithm alg)
        {
            CheckDocument(doc);
            var signedXml = RetrieveSignature(doc);
            return signedXml.CheckSignature(alg);
        }

        /// <summary>
        ///     Verifies the signature of the XmlElement instance using the key given as a parameter.
        /// </summary>
        /// <returns>
        ///     <code>true</code> if the element's signature can be verified. <code>false</code> if the signature could
        ///     not be verified.
        /// </returns>
        /// <exception cref="InvalidOperationException">if the XmlDocument instance does not contain a signed XML element.</exception>
        public static bool CheckSignature(XmlElement el, AsymmetricAlgorithm alg)
        {
            var signedXml = RetrieveSignature(el);
            if (signedXml == null)
            {
                Log.Error("Error retrieving signature form xml");
                throw new Exception("Error retrieving signature form xml");
            }

            if (alg == null)
            {
                Log.Error("AsymmetricAlgorithm cannot be null");
                throw new Exception("AsymmetricAlgorithm cannot be null");
            }

            try
            {
                Log.Debug("Assimetric Algorithm: {0}", alg.ToXmlString(false));
                
                //return signedXml.CheckSignature(alg);
                return CheckSignature(alg, signedXml);
            }
            catch (Exception ex)
            {
                Log.Error("Error checking xml signature - message: {0}", ex.Message);
                throw new Exception("Error checking xml signature", ex);
            }
            
        }

        public static bool CheckSignature(AsymmetricAlgorithm key, SignedXml xml)
        {
            Log.Debug("Verifing Signature with key:{0}, xml:{1}", key.SignatureAlgorithm, xml.ToString());
            if (key is null)
            {
                Log.Error("Key cannot be null");
                throw new ArgumentNullException(nameof(key));
            }
            
            SignatureDescription signatureDescription = CreateFromName<SignatureDescription>(xml.SignatureMethod);
            if (signatureDescription == null)
            {
                Log.Error("Error creating signature description");
                throw new CryptographicException(SR.Cryptography_Xml_SignatureDescriptionNotCreated);
            }
                
            Log.Debug("Sinature description: {0}", signatureDescription.KeyAlgorithm);
            // Let's see if the key corresponds with the SignatureMethod
            Type ta = Type.GetType(signatureDescription.KeyAlgorithm);
            if (ta == null)
            {
                Log.Error("Ta invalid");
                throw new Exception("Error geting signature object");
            }
            
            Log.Debug("Key type: {0}", ta.Name);
            
            if (!IsKeyTheCorrectAlgorithm(key, ta))
                return false;

            HashAlgorithm hashAlgorithm = signatureDescription.CreateDigest();
            
            Log.Debug("HashAlgorithm: {0}", hashAlgorithm.ToString());
            if (hashAlgorithm == null)
            {
                Log.Error("Error creating signature hash algorithm");
                throw new CryptographicException(SR.Cryptography_Xml_CreateHashAlgorithmFailed);
            }
            
            
            //byte[] hashval = GetC14NDigest(hashAlgorithm);
            
            MethodInfo dynMethod =  typeof(SignedXml).GetMethod("GetC14NDigest", 
                BindingFlags.NonPublic | BindingFlags.Instance);
            byte[] hashval = (byte[])dynMethod.Invoke(xml, new object[] { hashAlgorithm });
            
            if (hashval == null)
            {
                Log.Error("Error calculating hash value");
                throw new Exception("Hash value is invalid");
            }

            Log.Debug("Hash value: {0}", System.Text.Encoding.Default.GetString(hashval));
            
            //AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = signatureDescription.CreateDeformatter(key);

            var asymmetricSignatureDeformatter = new RSAPKCS1SignatureDeformatter();
            asymmetricSignatureDeformatter.SetKey(key);
            asymmetricSignatureDeformatter.SetHashAlgorithm(signatureDescription.DigestAlgorithm);
            
            
            Log.Debug("Verifing Signature deformarter");
            try
            {
                return asymmetricSignatureDeformatter.VerifySignature(hashval, xml.Signature.SignatureValue);
            }
            catch (Exception ex)
            {
                Log.Error("Error verifing signature on asymmetric signature");
                throw new Exception("Error verifing signature on asymmetric signature", ex);
            }
            
            

        }


        
        //private bool _bCacheValid;
        //private byte[] _digestedSignedInfo;
        
        private static bool IsKeyTheCorrectAlgorithm(AsymmetricAlgorithm key, Type expectedType)
        {
            Type actualType = key.GetType();

            if (actualType == expectedType)
                return true;

            // This check exists solely for compatibility with 4.6. Normally, we would expect "expectedType" to be the superclass type and
            // the actualType to be the subclass.
            if (expectedType.IsSubclassOf(actualType))
                return true;

            //
            // "expectedType" comes from the KeyAlgorithm property of a SignatureDescription. The BCL SignatureDescription classes have historically
            // denoted provider-specific implementations ("RSACryptoServiceProvider") rather than the base class for the algorithm ("RSA"). We could
            // change those (at the risk of creating other compat problems) but we have no control over third party SignatureDescriptions.
            //
            // So, in the absence of a better approach, walk up the parent hierarchy until we find the ancestor that's a direct subclass of
            // AsymmetricAlgorithm and treat that as the algorithm identifier.
            //
            while (expectedType != null && expectedType.BaseType != typeof(AsymmetricAlgorithm))
            {
                expectedType = expectedType.BaseType;
            }

            if (expectedType == null)
                return false;   // SignatureDescription specified something that isn't even a subclass of AsymmetricAlgorithm. For compatibility with 4.6, return false rather throw.

            if (actualType.IsSubclassOf(expectedType))
                return true;

            return false;
        }
        
        private static readonly char[] _invalidChars = new char[] { ',', '`', '[', '*', '&' };
        public static T CreateFromName<T>(string name) where T : class
        {
            if (name == null || name.IndexOfAny(_invalidChars) >= 0)
            {
                return null;
            }
            try
            {
                return (CryptoConfig.CreateFromName(name) ?? CreateFromKnownName(name)) as T;
            }
            catch (Exception)
            {
                return null;
            }
        }
        
        public static object CreateFromKnownName(string name) =>
            name switch
            {
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => new XmlDsigC14NTransform(),
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => new XmlDsigC14NWithCommentsTransform(),
                "http://www.w3.org/2001/10/xml-exc-c14n#" => new XmlDsigExcC14NTransform(),
                "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => new XmlDsigExcC14NWithCommentsTransform(),
                "http://www.w3.org/2000/09/xmldsig#base64" => new XmlDsigBase64Transform(),
                "http://www.w3.org/TR/1999/REC-xpath-19991116" => new XmlDsigXPathTransform(),
                "http://www.w3.org/TR/1999/REC-xslt-19991116" => new XmlDsigXsltTransform(),
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature" => new XmlDsigEnvelopedSignatureTransform(),
                "http://www.w3.org/2002/07/decrypt#XML" => new XmlDecryptionTransform(),
                "urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform" => new XmlLicenseTransform(),
                "http://www.w3.org/2000/09/xmldsig# X509Data" => new KeyInfoX509Data(),
                "http://www.w3.org/2000/09/xmldsig# KeyName" => new KeyInfoName(),
#pragma warning disable CA1416 // This call site is reachable on all platforms. 'DSAKeyValue' is unsupported on: 'ios', 'maccatalyst', 'tvos'
                "http://www.w3.org/2000/09/xmldsig# KeyValue/DSAKeyValue" => new DSAKeyValue(),
#pragma warning restore CA1416
                "http://www.w3.org/2000/09/xmldsig# KeyValue/RSAKeyValue" => new RSAKeyValue(),
                "http://www.w3.org/2000/09/xmldsig# RetrievalMethod" => new KeyInfoRetrievalMethod(),
                "http://www.w3.org/2001/04/xmlenc# EncryptedKey" => new KeyInfoEncryptedKey(),
                "http://www.w3.org/2000/09/xmldsig#dsa-sha1" => new DSASignatureDescription(),
                "System.Security.Cryptography.DSASignatureDescription" => new DSASignatureDescription(),
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => new RSAPKCS1SHA1SignatureDescription(),
                "System.Security.Cryptography.RSASignatureDescription" => new RSAPKCS1SHA1SignatureDescription(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => new RSAPKCS1SHA256SignatureDescription(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => new RSAPKCS1SHA384SignatureDescription(),
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => new RSAPKCS1SHA512SignatureDescription(),
                _ => null,
            };
        
        /// <summary>
        ///     Verify the given document using a KeyInfo instance. The KeyInfo instance's KeyClauses will be traversed for
        ///     elements that can verify the signature, eg. certificates or keys. If nothing is found, an exception is thrown.
        /// </summary>
        public static bool CheckSignature(XmlDocument doc, KeyInfo keyinfo)
        {
            CheckDocument(doc);
            var signedXml = RetrieveSignature(doc);

            AsymmetricAlgorithm alg = null;
            X509Certificate2 cert = null;
            foreach (KeyInfoClause clause in keyinfo)
            {
                if (clause is RSAKeyValue)
                {
                    var key = (RSAKeyValue) clause;
                    alg = key.Key;
                    break;
                }

                if (clause is KeyInfoX509Data)
                {
                    var x509Data = (KeyInfoX509Data) clause;
                    var count = x509Data.Certificates.Count;
                    cert = (X509Certificate2) x509Data.Certificates[count - 1];
                }
                else if (clause is DSAKeyValue)
                {
                    var key = (DSAKeyValue)clause;
                    alg = key.Key;
                    break;
                }
            }

            if (alg == null && cert == null)
            {
                throw new InvalidOperationException("Unable to locate the key or certificate to verify the signature.");
            }

            if (alg != null)
            {
                return signedXml.CheckSignature(alg);
            }

            return signedXml.CheckSignature(cert, true);
        }

        /// <summary>
        ///     Attempts to retrieve an asymmetric key from the KeyInfoClause given as parameter.
        /// </summary>
        /// <param name="keyInfoClause"></param>
        /// <returns>null if the key could not be found.</returns>
        public static AsymmetricAlgorithm ExtractKey(KeyInfoClause keyInfoClause)
        {
            if (keyInfoClause is RSAKeyValue)
            {
                var key = (RSAKeyValue) keyInfoClause;
                return key.Key;
            }

            if (keyInfoClause is KeyInfoX509Data)
            {
                var cert = GetCertificateFromKeyInfo((KeyInfoX509Data) keyInfoClause);

                return cert?.PublicKey.GetRSAPublicKey();
            }

            if (keyInfoClause is DSAKeyValue)
            {
                var key = (DSAKeyValue) keyInfoClause;
                return key.Key;
            }

            return null;
        }

        /// <summary>
        ///     Gets the certificate from key info.
        /// </summary>
        /// <param name="keyInfo">The key info.</param>
        /// <returns>The last certificate in the chain</returns>
        public static X509Certificate2 GetCertificateFromKeyInfo(KeyInfoX509Data keyInfo)
        {
            var count = keyInfo.Certificates.Count;
            if (count == 0)
            {
                return null;
            }

            var cert = (X509Certificate2) keyInfo.Certificates[count - 1];
            return cert;
        }

        /// <summary>
        ///     Checks if a document contains a signature.
        /// </summary>
        public static bool IsSigned(XmlDocument doc)
        {
            CheckDocument(doc);
            var nodeList =
                doc.GetElementsByTagName(Signature.ELEMENT_NAME, Saml2Constants.XMLDSIG);

            return nodeList.Count > 0;
        }

        /// <summary>
        ///     Checks if an element contains a signature.
        /// </summary>
        public static bool IsSigned(XmlElement el)
        {
            CheckDocument(el);
            var nodeList =
                el.GetElementsByTagName(Signature.ELEMENT_NAME, Saml2Constants.XMLDSIG);

            return nodeList.Count > 0;
        }

        /// <summary>
        ///     Signs an XmlDocument with an xml signature using the signing certificate given as argument to the method.
        /// </summary>
        /// <param name="doc">The XmlDocument to be signed</param>
        /// <param name="id">The is of the topmost element in the xmldocument</param>
        /// <param name="cert">The certificate used to sign the document</param>
        public static void SignDocument(XmlDocument doc, string id, X509Certificate2 cert)
        {
            var signedXml = new SignedXml(doc);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SigningKey = cert.GetRSAPrivateKey();

            // Retrieve the value of the "ID" attribute on the root assertion element.
            var reference = new Reference("#" + id);

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);

            // Include the public key of the certificate in the assertion.
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert, X509IncludeOption.WholeChain));

            signedXml.ComputeSignature();

            // Append the computed signature. The signature must be placed as the sibling of the Issuer element.
            var nodes = doc.DocumentElement.GetElementsByTagName("Issuer", Saml2Constants.ASSERTION);

            // doc.DocumentElement.InsertAfter(doc.ImportNode(signedXml.GetXml(), true), nodes[0]);            
            nodes[0].ParentNode.InsertAfter(doc.ImportNode(signedXml.GetXml(), true), nodes[0]);
        }

        /// <summary>
        ///     Returns the KeyInfo element that is included with the signature in the document.
        /// </summary>
        /// <exception cref="InvalidOperationException">if the document is not signed.</exception>
        public static KeyInfo ExtractSignatureKeys(XmlDocument doc)
        {
            CheckDocument(doc);
            var signedXml = new SignedXml(doc.DocumentElement);

            var nodeList = doc.GetElementsByTagName(Signature.ELEMENT_NAME, Saml2Constants.XMLDSIG);
            if (nodeList.Count == 0)
            {
                throw new InvalidOperationException("The XmlDocument does not contain a signature.");
            }

            signedXml.LoadXml((XmlElement) nodeList[0]);
            return signedXml.KeyInfo;
        }

        /// <summary>
        ///     Returns the KeyInfo element that is included with the signature in the element.
        /// </summary>
        /// <exception cref="InvalidOperationException">if the document is not signed.</exception>
        public static KeyInfo ExtractSignatureKeys(XmlElement el)
        {
            CheckDocument(el);
            var signedXml = new SignedXml(el);

            var nodeList = el.GetElementsByTagName(Signature.ELEMENT_NAME, Saml2Constants.XMLDSIG);
            if (nodeList.Count == 0)
            {
                throw new InvalidOperationException("The XmlDocument does not contain a signature.");
            }

            signedXml.LoadXml((XmlElement) nodeList[0]);
            return signedXml.KeyInfo;
        }

        /// <summary>
        ///     Checks the signature using a list of certificates
        /// </summary>
        /// <param name="signedXml">Signed xml object for signature</param>
        /// <param name="trustedCertificates">List of certificates</param>
        /// <returns>true if signature is verified</returns>
        private static bool CheckSignature(SignedXml signedXml, IEnumerable<X509Certificate2> trustedCertificates)
        {
            foreach (var cert in trustedCertificates)
            {
                if (signedXml.CheckSignature(cert.PublicKey.GetRSAPublicKey()))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        ///     Digs the &lt;Signature&gt; element out of the document.
        /// </summary>
        /// <exception cref="InvalidOperationException">if the document does not contain a signature.</exception>
        private static SignedXml RetrieveSignature(XmlDocument doc)
        {
            return RetrieveSignature(doc.DocumentElement);
        }

        /// <summary>
        ///     Digs the &lt;Signature&gt; element out of the document.
        /// </summary>
        /// <exception cref="InvalidOperationException">if the document does not contain a signature.</exception>
        private static SignedXml RetrieveSignature(XmlElement el)
        {
            var doc = new XmlDocument {PreserveWhitespace = true};
            doc.LoadXml(el.OuterXml);
            var signedXml = new SignedXml(doc);
            var nodeList = doc.GetElementsByTagName(Signature.ELEMENT_NAME, Saml2Constants.XMLDSIG);
            if (nodeList.Count == 0)
            {
                throw new InvalidOperationException("Document does not contain a signature to verify.");
            }

            try
            {
                var element = (XmlElement)nodeList[0];
                if (element == null)
                {
                    throw new Exception("Error extracting xmlElement");
                }
                Log.Debug("Trying to load xmlElement {0}", element.Name);
                signedXml.LoadXml(element);
                //signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

                Log.Debug("SignedXML loaded");
                Log.Debug("SignedXML signatureMethod loaded: {0}", signedXml.SignatureMethod);

                // verify that the inlined signature has a valid reference uri
                VerifyRererenceUri(signedXml, el.GetAttribute("ID"));

                return signedXml;
            }
            catch (Exception ex)
            {
                Log.Error("Error RetrieveSignature - message:{0}", ex);
                throw new Exception("Error RetrieveSignature", ex);
            }
        }

        /// <summary>
        ///     Verifies that the reference uri (if any) points to the correct element.
        /// </summary>
        /// <param name="signedXml">the ds:signature element</param>
        /// <param name="id">the expected id referenced by the ds:signature element</param>
        private static void VerifyRererenceUri(SignedXml signedXml, string id)
        {
            if (id == null)
            {
                throw new InvalidOperationException("Cannot match null id");
            }

            if (signedXml.SignedInfo.References.Count > 0)
            {
                var reference = (Reference) signedXml.SignedInfo.References[0];
                var uri = reference.Uri;

                // empty uri is okay - indicates that everything is signed
                if (uri?.Length > 0)
                {
                    if (!uri.StartsWith("#"))
                    {
                        throw new InvalidOperationException(
                            "Signature reference URI is not a document fragment reference. Uri = '" + uri + "'");
                    }
                    else if (uri.Length < 2 || !id.Equals(uri.Substring(1)))
                    {
                        throw new InvalidOperationException("Rererence URI = '" + uri.Substring(1) +
                                                            "' does not match expected id = '" + id + "'");
                    }
                }
            }
            else
            {
                throw new InvalidOperationException("No references in Signature element");
            }
        }

        /// <summary>
        ///     Do checks on the document given. Every public method accepting a XmlDocument instance as parameter should
        ///     call this method before continuing.
        /// </summary>
        private static void CheckDocument(XmlDocument doc)
        {
            if (!doc.PreserveWhitespace)
            {
                throw new InvalidOperationException(
                    "The XmlDocument must have its \"PreserveWhitespace\" property set to true when a signed document is loaded.");
            }
        }

        /// <summary>
        ///     Do checks on the element given. Every public method accepting a XmlElement instance as parameter should
        ///     call this method before continuing.
        /// </summary>
        private static void CheckDocument(XmlElement el)
        {
            if (!el.OwnerDocument.PreserveWhitespace)
            {
                throw new InvalidOperationException(
                    "The XmlDocument must have its \"PreserveWhitespace\" property set to true when a signed document is loaded.");
            }
        }

        private static List<X509Certificate2> GetCertificates(XmlDocument doc)
        {
            var lCert = new List<X509Certificate2>();
            var nodeList = doc.GetElementsByTagName("ds:X509Certificate");

            if (nodeList.Count == 0)
            {
                nodeList = doc.GetElementsByTagName("X509Certificate");
            }

            foreach (XmlNode xn in nodeList)
            {
                try
                {
                    //var xc = new X509Certificate2(Convert.FromBase64String(xn.InnerText));
                    var xc = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(xn.InnerText));
                    
                    lCert.Add(xc);
                }
                catch
                {
                }
            }

            return lCert;
        }
    }
}