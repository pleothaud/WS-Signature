namespace WS_Signature2
{

    using System;

    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Cryptography.Xml;
    using System.Xml;
    using System.Runtime.InteropServices;

    [ComVisible(true)]
    public class SOAPSigningUtility {

        [ComVisible(true)]
		public static X509Certificate2 GetCertificate(String certName) {
			// X509Store my = new X509Store(StoreName.My, StoreLocation.LocalMachine);
			X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
			my.Open(OpenFlags.ReadOnly);
			X509Certificate2 signingCert = null;
			foreach (X509Certificate2 cert in my.Certificates) {
				if (cert.Subject.Contains(certName)) {
					signingCert = cert;
					break;
				}
			}
			if (signingCert == null) {
				throw new CryptographicException("Unable to find certificate in the CurrentUser store");
			}
			return signingCert;
		}

		[ComVisible(true)]
		public static X509Certificate2 GetCertificateByIssuerSerial(String Issuer, String serial) {
			// X509Store my = new X509Store(StoreName.My, StoreLocation.LocalMachine);
			X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
			my.Open(OpenFlags.ReadOnly);
			X509Certificate2 signingCert = null;
			foreach (X509Certificate2 cert in my.Certificates) {
				// Windows bug : certificates with DN like 
				//		CN =SUNCA, OU=JWS, O=SUN, ST=Some-State, C=AU 
				// are registered as 
				//		CN =SUNCA, OU=JWS, O=SUN, S=Some-State, C=AU
				// So we need to rewrite 'S=' into 'ST=' to compare issuers
				String realIssuer = cert.Issuer.Replace("S=", "ST=");
				if (Int32.Parse(cert.SerialNumber).Equals(Int32.Parse(serial))) {
					if (Issuer.Equals(realIssuer)) {
						signingCert = cert;
						break;
					}
				}
			}
			if (signingCert == null) {
				throw new CryptographicException("Unable to find certificate in the CurrentUser store");
			}
			return signingCert;
		}

		[ComVisible(true)]
		public static String AddAdressingHeaders(String xmlString, String ToString, String ActionString, String ReplyToAddressString, String FaultToAddressString) {

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(xmlString);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			XmlElement envelopeNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope", ns) as XmlElement;
			XmlElement headerNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header", ns) as XmlElement;
			if (headerNode == null) {
				headerNode = xmlDoc.CreateElement("s", "Header", "http://www.w3.org/2003/05/soap-envelope");
				envelopeNode.AppendChild(headerNode);
			}

			XmlElement toNode = xmlDoc.CreateElement("wsa", "To", "http://www.w3.org/2005/08/addressing");
			toNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_2");
			toNode.InnerText = ToString;
			headerNode.AppendChild(toNode);

			XmlElement actionNode = xmlDoc.CreateElement("wsa", "Action", "http://www.w3.org/2005/08/addressing");
			actionNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_3");
			actionNode.SetAttribute("mustUnderstand", "http://www.w3.org/2003/05/soap-envelope", "true");
			actionNode.InnerText = ActionString;
			headerNode.AppendChild(actionNode);

			XmlElement replyToNode = xmlDoc.CreateElement("wsa", "ReplyTo", "http://www.w3.org/2005/08/addressing");
			replyToNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_4");
			XmlElement replyToAddressNode = xmlDoc.CreateElement("wsa", "Address", "http://www.w3.org/2005/08/addressing");
			replyToAddressNode.InnerText = ReplyToAddressString;
			replyToNode.AppendChild(replyToAddressNode);
			headerNode.AppendChild(replyToNode);

			XmlElement faultToNode = xmlDoc.CreateElement("wsa", "FaultTo", "http://www.w3.org/2005/08/addressing");
			faultToNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_5");
			XmlElement faultToAddressNode = xmlDoc.CreateElement("wsa", "Address", "http://www.w3.org/2005/08/addressing");
			faultToAddressNode.InnerText = FaultToAddressString;
			faultToNode.AppendChild(faultToAddressNode);
			headerNode.AppendChild(faultToNode);

			XmlElement messageIDNode = xmlDoc.CreateElement("wsa", "MessageID", "http://www.w3.org/2005/08/addressing");
			messageIDNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_6");
			messageIDNode.InnerText = "uuid:" + Guid.NewGuid().ToString();
			headerNode.AppendChild(messageIDNode);

			return xmlDoc.InnerXml;
		}

		[ComVisible(true)]
		public static String AddTimestampSecurityHeader(String xmlString) {
			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(xmlString);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			XmlElement envelopeNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope", ns) as XmlElement;
			XmlElement headerNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header", ns) as XmlElement;
			if (headerNode == null) {
				headerNode = xmlDoc.CreateElement("s", "Header", "http://www.w3.org/2003/05/soap-envelope");
				envelopeNode.AppendChild(headerNode);
			}
			XmlElement securityNode = xmlDoc.DocumentElement.SelectSingleNode("//wsse:Security", ns) as XmlElement;
			if (securityNode == null) {
				securityNode = xmlDoc.CreateElement("wsse", "Security", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
				headerNode.AppendChild(securityNode);
			}

			XmlElement timestampNode = xmlDoc.CreateElement("wsu", "Timestamp", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			timestampNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_7");

			XmlElement createdNode = xmlDoc.CreateElement("wsu", "Created", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			createdNode.InnerText = DateTime.Now.AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ssZ");
			timestampNode.AppendChild(createdNode);

			XmlElement expiresNode = xmlDoc.CreateElement("wsu", "Expires", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			expiresNode.InnerText = DateTime.Now.AddHours(-1).AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ssZ");
			timestampNode.AppendChild(expiresNode);

			securityNode.AppendChild(timestampNode);
			return xmlDoc.InnerXml;
		}

		[ComVisible(true)]
		public static String SignXml(String xmlString, String signingPrivateKeyCertName) {
			if (xmlString == null)
				throw new ArgumentException("xmlString");
			if (signingPrivateKeyCertName == null)
				throw new ArgumentException("signingCertName");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(xmlString);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			XmlElement headerNode = xmlDoc.DocumentElement.SelectSingleNode("//s:Header", ns) as XmlElement;
			XmlElement securityNode = xmlDoc.DocumentElement.SelectSingleNode("//wsse:Security", ns) as XmlElement;
			if (securityNode == null) securityNode = xmlDoc.CreateElement("wsse", "Security", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");

			X509Certificate2 signingCert = GetCertificate(signingPrivateKeyCertName);
			XmlElement binarySecurityTokenNode = xmlDoc.CreateElement("wse", "BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			binarySecurityTokenNode.SetAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
			binarySecurityTokenNode.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
			binarySecurityTokenNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_BinarySecurityToken1");
			binarySecurityTokenNode.InnerText = Convert.ToBase64String(signingCert.GetRawCertData());
			securityNode.AppendChild(binarySecurityTokenNode);
			headerNode.AppendChild(securityNode);

			RSACryptoServiceProvider key = (RSACryptoServiceProvider)signingCert.PrivateKey;
			SignedXmlWithId signedXml = new SignedXmlWithId(xmlDoc);
			signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
			signedXml.SigningKey = key;
			KeyInfo keyInfo = new KeyInfo();
			keyInfo.AddClause(new SecurityTokenReference("_BinarySecurityToken1"));
			signedXml.KeyInfo = keyInfo;
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			// Create a reference to be signed.
			Reference reference = new Reference("#_1");
			reference.DigestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
			//XmlDsigC14NTransform transform = new XmlDsigC14NTransform();
			XmlDsigExcC14NTransform transform = new XmlDsigExcC14NTransform();
			reference.AddTransform(transform);
			signedXml.AddReference(reference);

			Reference reference2 = new Reference("#_2");
			reference2.AddTransform(transform);
			signedXml.AddReference(reference2);

			Reference reference3 = new Reference("#_3");
			reference3.AddTransform(transform);
			signedXml.AddReference(reference3);

			Reference reference4 = new Reference("#_4");
			reference4.AddTransform(transform);
			signedXml.AddReference(reference4);

			Reference reference5 = new Reference("#_5");
			reference5.AddTransform(transform);
			signedXml.AddReference(reference5);

			Reference reference6 = new Reference("#_6");
			reference6.AddTransform(transform);
			signedXml.AddReference(reference6);

			Reference reference7 = new Reference("#_7");
			reference7.AddTransform(transform);
			signedXml.AddReference(reference7);

			signedXml.ComputeSignature();
			XmlElement signedElement = signedXml.GetXml();
			securityNode.AppendChild(signedElement);
			xmlDoc.Save("SignedSOAP.xml");
			return xmlDoc.InnerXml;
		}

		// Verify the signature of an XML file against an asymmetric algorithm and return the result.
		[ComVisible(true)]
		public static Boolean VerifyXml(String xmlString, String signingCertName) {
			if (xmlString == null)
				throw new ArgumentException("xmlString");
			if (signingCertName == null)
				throw new ArgumentException("signingCert");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(xmlString);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("e", "http://www.w3.org/2001/04/xmlenc#");
			ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			ns.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			XmlElement SignatureNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/ds:Signature", ns) as XmlElement;

			X509Certificate2 signingCert = GetCertificate(signingCertName);
			SignedXmlWithId signedXml = new SignedXmlWithId(xmlDoc);
			// signedXml.SigningKey
			signedXml.LoadXml(SignatureNode);
			//return signedXml.CheckSignature(signedXml.SigningKey);
			return signedXml.CheckSignature((RSACryptoServiceProvider)signingCert.PublicKey.Key);
		}

		// Verify the signature of an XML file against an asymmetric algorithm and return the result.
		[ComVisible(true)]
		public static Boolean VerifyXml(String xmlString) {
			if (xmlString == null)
				throw new ArgumentException("xmlString");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(xmlString);

			// /S:Envelope/S:Header/wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/ds:X509Data/ds:X509IssuerSerial/ds:X509IssuerName
			// /S:Envelope/S:Header/wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/ds:X509Data/ds:X509IssuerSerial/ds:X509SerialNumber
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("e", "http://www.w3.org/2001/04/xmlenc#");
			ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			ns.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			XmlElement X509IssuerNameNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/ds:X509Data/ds:X509IssuerSerial/ds:X509IssuerName", ns) as XmlElement;
			XmlElement X509SerialNumberNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/ds:X509Data/ds:X509IssuerSerial/ds:X509SerialNumber", ns) as XmlElement;
			X509Certificate2 signingCert = GetCertificateByIssuerSerial(X509IssuerNameNode.InnerText, X509SerialNumberNode.InnerText);

			XmlElement SignatureNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/ds:Signature", ns) as XmlElement;

			SignedXmlWithId signedXml = new SignedXmlWithId(xmlDoc);
			signedXml.LoadXml(SignatureNode);
			return signedXml.CheckSignature((RSACryptoServiceProvider)signingCert.PublicKey.Key);

		}

		// Verify the signature of an XML file against an asymmetric algorithm and return the result.
		[ComVisible(true)]
		public static Boolean VerifyXml(String xmlString, X509Certificate2 signingCert) {
			if (xmlString == null)
				throw new ArgumentException("xmlString");
			if (signingCert == null)
				throw new ArgumentException("signingCert");
			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(xmlString);
			SignedXmlWithId signedXml = new SignedXmlWithId(xmlDoc);
			// signedXml.SigningKey
			XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");
			if (nodeList.Count <= 0) {
				throw new CryptographicException("Verification failed: No Signature was found in the document.");
			}
			// This example only supports one signature for the entire XML document.  Throw an exception if more than one signature was found.
			if (nodeList.Count >= 2) {
				throw new CryptographicException("Verification failed: More that one signature was found for the document.");
			}
			signedXml.LoadXml((XmlElement)nodeList[0]);
			return signedXml.CheckSignature((RSACryptoServiceProvider)signingCert.PublicKey.Key);
		}

		[ComVisible(true)]
		public static String Encrypt(String xmlString, String EncryptionCertificateName, string ElementToEncryptLocalName, string ElementToEncryptNamespace) {

			if (xmlString == null)
				throw new ArgumentNullException("xmlString");
			if (ElementToEncryptLocalName == null)
				throw new ArgumentNullException("ElementToEncryptName");
			if (EncryptionCertificateName == null)
				throw new ArgumentNullException("signingCertName");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(xmlString);

			XmlElement elementToEncrypt = null;
			if (ElementToEncryptNamespace == null) {
				elementToEncrypt = xmlDoc.GetElementsByTagName(ElementToEncryptLocalName)[0] as XmlElement;
			} else {
				elementToEncrypt = xmlDoc.GetElementsByTagName(ElementToEncryptLocalName, ElementToEncryptNamespace)[0] as XmlElement;
			}
			// Throw an XmlException if the element was not found.
			if (elementToEncrypt == null) {
				throw new XmlException("The specified element was not found");
			}

			// Create a symmetric AES session key 
			RijndaelManaged sessionKey = new RijndaelManaged();
			sessionKey.KeySize = 128;

			// Now create the EncryptedKey block, that will contain the symmetric session key encrypted with the recipient's public key retrieved from its certificate
			EncryptedKey ek = new EncryptedKey();
			ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
			//ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl);

			// Retrieve the RSA asymmetric encryption key from the recipient's certificate
			X509Certificate2 EncryptionCertificate = GetCertificate(EncryptionCertificateName);
			RSACryptoServiceProvider RSA = (RSACryptoServiceProvider)EncryptionCertificate.PublicKey.Key;
			// Encrypt the symmetric session key with this asymmetric key
			byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, RSA, false);
			ek.CipherData = new CipherData(encryptedKey);

			// Add a KeyInfo block to the EncryptedKey referencing the recipient's public key
			KeyInfoX509Data kix509 = new KeyInfoX509Data();
			kix509.AddIssuerSerial(EncryptionCertificate.Issuer, EncryptionCertificate.SerialNumber);
			ek.KeyInfo.AddClause(kix509);

			// Create a DataReference to the EncrytedData that will be encrypted by the symmetric session key
			// We have to do that because IDMS uses an EncryptedKey block outside of the EncryptedData/KeyInfo block
			DataReference ref1 = new DataReference();
			ref1.Uri = "#_payload";
			ek.AddReference(ref1);

			EncryptedData edElement = new EncryptedData();
			edElement.Type = EncryptedXml.XmlEncElementContentUrl;
			edElement.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES128Url);
			edElement.Id = "_payload";
			edElement.CipherData = new CipherData();

			edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));

			EncryptedXml eXml = new EncryptedXml();
			byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, false);
			edElement.CipherData.CipherValue = encryptedElement;

			EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);

			Console.WriteLine("Raw encrypted XML : \n" + xmlDoc.InnerXml);

			try {
				/*
				 * We then need to reformat the whole message.
				 * 
				 * So far, the EncryptedKey block generated by .Net is in /S:Envelope/S:Body/e:EncryptdData/ds:KeyInfo under this format : 
				 * 
				 * 	<ds:KeyInfo>
				 * 		<xenc:EncryptedKey 
				 * 				xmlns:ns17="http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512" 
				 * 				xmlns:ns16="http://schemas.xmlsoap.org/soap/envelope/" 
				 * 				Id="_5007">
				 * 			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
				 * 			<ds:KeyInfo>
				 * 				<ds:X509Data>
				 * 					<ds:X509IssuerSerial>
				 * 						<ds:X509IssuerName>CN=SUNCA, OU=JWS, O=SUN, ST=Some-State, C=AU</ds:X509IssuerName>
				 * 						<ds:X509SerialNumber>2</ds:X509SerialNumber>
				 * 					</ds:X509IssuerSerial>
				 * 				</ds:X509Data>
				 * 			</ds:KeyInfo>
				 * 			<xenc:CipherData>
				 * 				<xenc:CipherValue>c6DN7B.....O/BATrcM=</xenc:CipherValue>
				 * 			</xenc:CipherData>
				 * 			<xenc:ReferenceList>
				 * 				<xenc:DataReference URI="#_payload" />
				 * 			</xenc:ReferenceList>
				 * 		</xenc:EncryptedKey>
				 * 	</ds:KeyInfo>
				 * 	
				 * IDMS waits for the EncryptedKey block in /S:Envelope/S:Header/wsse:/Security and in the following format :
				 * 	
				 * 	<xenc:EncryptedKey Id="_5007">
				 * 		<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
				 * 		<ds:KeyInfo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="KeyInfoType">
				 * 			<wsse:SecurityTokenReference>
				 * 				<ds:X509Data>
				 * 					<ds:X509IssuerSerial>
				 * 						<ds:X509IssuerName>CN=SUNCA, OU=JWS, O=SUN, ST=Some-State, C=AU</ds:X509IssuerName>
				 * 						<ds:X509SerialNumber>2</ds:X509SerialNumber>
				 * 					</ds:X509IssuerSerial>
				 * 				</ds:X509Data>
				 * 			</wsse:SecurityTokenReference>
				 * 		</ds:KeyInfo>
				 * 		<xenc:CipherData>
				 * 			<xenc:CipherValue>Ah1EDF.....+AchU=</xenc:CipherValue>
				 * 		</xenc:CipherData>
				 * 		<xenc:ReferenceList>
				 * 			<xenc:DataReference URI="#_payload" />
				 * 		</xenc:ReferenceList>
				 * 	</xenc:EncryptedKey>
				 */
				XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
				ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
				ns.AddNamespace("e", "http://www.w3.org/2001/04/xmlenc#");
				ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
				ns.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
				XmlElement encryptedData = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body/e:EncryptedData", ns) as XmlElement;
				XmlElement keyInfo = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body/e:EncryptedData/ds:KeyInfo", ns) as XmlElement;
				XmlElement EncryptedKey = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body/e:EncryptedData/ds:KeyInfo/e:EncryptedKey", ns) as XmlElement;
				XmlElement ekKeyInfo = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body/e:EncryptedData/ds:KeyInfo/e:EncryptedKey/ds:KeyInfo", ns) as XmlElement;
				XmlElement ekKeyInfoX509Data = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body/e:EncryptedData/ds:KeyInfo/e:EncryptedKey/ds:KeyInfo/ds:X509Data", ns) as XmlElement;
				XmlElement Signature = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/ds:Signature", ns) as XmlElement;

				XmlElement str = xmlDoc.CreateElement("wsse", "SecurityTokenReference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
				str.AppendChild(ekKeyInfoX509Data);
				ekKeyInfo.AppendChild(str);

				EncryptedKey = (XmlElement)keyInfo.RemoveChild(EncryptedKey);
				keyInfo = (XmlElement)encryptedData.RemoveChild(keyInfo);

				XmlElement security = xmlDoc.DocumentElement.SelectSingleNode("//wsse:Security", ns) as XmlElement;
				security.InsertBefore(EncryptedKey, Signature);
			} catch (Exception e) {
				Console.WriteLine(e.Message);
				Console.WriteLine(e.StackTrace);
			}
			return xmlDoc.InnerXml;
		}


		[ComVisible(true)]
		public static String Decrypt(String xmlString, string signingCertName) {
			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(xmlString);
			X509Certificate2 signingCert = GetCertificate(signingCertName);

			EncryptedXml exml = new EncryptedXml(xmlDoc);
			exml.AddKeyNameMapping(signingCert.FriendlyName, (RSA)signingCert.PrivateKey);
			try {
				exml.DecryptDocument();
			} catch (Exception e) {
				Console.WriteLine("Exception : " + e.Message);
				Console.WriteLine("Exception : " + e.StackTrace);
			}
			return xmlDoc.InnerXml;
		}

		[ComVisible(true)]
		public static string Decrypt(String xmlString) {

			if (xmlString == null)
				throw new ArgumentNullException("xmlString");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(xmlString);

			/*
			 * The EncryptedKey block sent by IDMS is in /S:Envelope/S:Header/wsse:/Security and in the following format :
			 * 
			 * 	<xenc:EncryptedKey Id="_5007">
			 * 		<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
			 * 		<ds:KeyInfo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="KeyInfoType">
			 * 			<wsse:SecurityTokenReference>
			 * 				<ds:X509Data>
			 * 					<ds:X509IssuerSerial>
			 * 						<ds:X509IssuerName>CN=SUNCA, OU=JWS, O=SUN, ST=Some-State, C=AU</ds:X509IssuerName>
			 * 						<ds:X509SerialNumber>3</ds:X509SerialNumber>
			 * 					</ds:X509IssuerSerial>
			 * 				</ds:X509Data>
			 * 			</wsse:SecurityTokenReference>
			 * 		</ds:KeyInfo>
			 * 		<xenc:CipherData>
			 * 			<xenc:CipherValue>Ah1EDF.....+AchU=</xenc:CipherValue>
			 * 		</xenc:CipherData>
			 * 		<xenc:ReferenceList>
			 * 			<xenc:DataReference URI="#_5008" />
			 * 		</xenc:ReferenceList>
			 * 	</xenc:EncryptedKey>
			 * 	
			 * 	It must end up in /S:Envelope/S:Body/e:EncryptdData/ds:KeyInfo under this format : 
			 * 	
			 * 	<ds:KeyInfo>
			 * 		<xenc:EncryptedKey 
			 * 				xmlns:ns17="http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512" 
			 * 				xmlns:ns16="http://schemas.xmlsoap.org/soap/envelope/" 
			 * 				Id="_5007">
			 * 			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
			 * 			<ds:KeyInfo>
			 * 				<ds:KeyName>CN=xwssecurityclient,OU=SUN,O=Internet Widgits Pty Ltd,ST=Some-State,C=AU</ds:KeyName>
			 * 			</ds:KeyInfo>
			 * 			<xenc:CipherData>
			 * 				<xenc:CipherValue>c6DN7B.....O/BATrcM=</xenc:CipherValue>
			 * 			</xenc:CipherData>
			 * 			<xenc:ReferenceList>
			 * 				<xenc:DataReference URI="#_5008" />
			 * 			</xenc:ReferenceList>
			 * 		</xenc:EncryptedKey>
			 * 	</ds:KeyInfo>
			 */

			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("e", "http://www.w3.org/2001/04/xmlenc#");
			ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			ns.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");

			try {

				XmlElement EncryptedKeyNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/e:EncryptedKey", ns) as XmlElement;
				XmlElement CipherDataNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/e:EncryptedKey/e:CipherData", ns) as XmlElement;

				XmlElement KeyInfoNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/e:EncryptedKey/ds:KeyInfo", ns) as XmlElement;
				XmlElement SecurityTokenReferenceNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/e:EncryptedKey/ds:KeyInfo/wsse:SecurityTokenReference", ns) as XmlElement;
				XmlElement X509DataNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/e:EncryptedKey/ds:KeyInfo/wsse:SecurityTokenReference/ds:X509Data", ns) as XmlElement;
				XmlElement X509IssuerNameNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/e:EncryptedKey/ds:KeyInfo/wsse:SecurityTokenReference/ds:X509Data/ds:X509IssuerSerial/ds:X509IssuerName", ns) as XmlElement;
				XmlElement X509SerialNumberNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/e:EncryptedKey/ds:KeyInfo/wsse:SecurityTokenReference/ds:X509Data/ds:X509IssuerSerial/ds:X509SerialNumber", ns) as XmlElement;

				KeyInfoNode.RemoveChild(SecurityTokenReferenceNode);
				KeyInfoNode.AppendChild(X509DataNode);
				KeyInfoNode.RemoveAttribute("xmlns:xsi");
				KeyInfoNode.RemoveAttribute("xsi:type");
				X509Certificate2 cert = GetCertificateByIssuerSerial(X509IssuerNameNode.InnerText, X509SerialNumberNode.InnerText);
				String KeyNameString = cert.FriendlyName;
				XmlElement KeyName = xmlDoc.CreateElement("ds", "KeyName", "http://www.w3.org/2000/09/xmldsig#");
				KeyName.InnerText = KeyNameString;
				KeyInfoNode.ReplaceChild(KeyName, X509DataNode);

				//EncryptedKey.RemoveChild(ReferenceList);
				EncryptedKeyNode.InsertBefore(KeyInfoNode, CipherDataNode);

				XmlElement EncryptedDataNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body/e:EncryptedData", ns) as XmlElement;
				XmlElement CipherData = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body/e:EncryptedData/e:CipherData", ns) as XmlElement;

				EncryptedData encData = new EncryptedData();
				encData.LoadXml(EncryptedDataNode);

				XmlElement newKeyInfo = xmlDoc.CreateElement("ds", "KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
				newKeyInfo.AppendChild(EncryptedKeyNode);
				EncryptedDataNode.InsertBefore(newKeyInfo, CipherData);

				Console.WriteLine("\n\nModified enc xml: " + xmlDoc.InnerXml + "\n\n");

				EncryptedXml exml = new EncryptedXml(xmlDoc);
				exml.AddKeyNameMapping(KeyNameString, (RSA)cert.PrivateKey);
				exml.DecryptDocument();
				//exml.DecryptData(encData, exml.GetDecryptionKey(encData, "http://www.w3.org/2001/04/xmlenc#aes128-cbc"));
			} catch (Exception e) {
				Console.WriteLine("Exception : " + e.Message);
				Console.WriteLine("Exception : " + e.StackTrace);
			}
			return xmlDoc.InnerXml;
		}
	}

	[ComVisible(true)]
    public class SignedXmlWithId : SignedXml
    {
        public SignedXmlWithId(XmlDocument xml) : base(xml) { }
        public SignedXmlWithId(XmlElement xmlElement) : base(xmlElement) { }
        public override XmlElement GetIdElement(XmlDocument doc, string id)
        {
            // check to see if it's a standard ID reference
            XmlElement idElem = base.GetIdElement(doc, id);
            if (idElem == null)
            {
                XmlNamespaceManager nsManager = new XmlNamespaceManager(doc.NameTable);
                nsManager.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
                idElem = doc.SelectSingleNode("//*[@wsu:Id=\"" + id + "\"]", nsManager) as XmlElement;
            }
            return idElem;
        }
    }

    [ComVisible(true)]
    public class SecurityTokenReference : KeyInfoClause
    {
        public string BinarySecurityTokenId { get; set; }
        public SecurityTokenReference(string binarySecurityToken)
        {
            this.BinarySecurityTokenId = binarySecurityToken;
        }
        public override XmlElement GetXml()
        {
            XmlDocument doc = new XmlDocument();
            XmlElement strXmlElement = doc.CreateElement("wse", "SecurityTokenReference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            doc.AppendChild(strXmlElement);
            XmlElement reference = doc.CreateElement("wse", "Reference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            reference.SetAttribute("URI", "#" + BinarySecurityTokenId);
            reference.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509");
            strXmlElement.AppendChild(reference);
            return strXmlElement;
        }
        public override void LoadXml(XmlElement element)
        {
            throw new NotImplementedException();
        }
    }

}
