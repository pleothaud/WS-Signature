namespace WS_Signature {

	using System;

	using System.Security.Cryptography;
	using System.Security.Cryptography.X509Certificates;
	using System.Security.Cryptography.Xml;
	using System.Xml;
	using System.Runtime.InteropServices;
	using System.Net;
	using System.Text;
	using System.IO;

	/// <summary>
	/// Utility Class to sign/verify and encrypt/decrypt the messages exchanged with the IDMS server.
	/// 
	/// As a reminder, when using certificates based, asymmetric cryptography :
	/// 
	///		- For XML Signatures (XML-Dsig standard) :
	///			- Signatures are created with the private key of the signing entity (here the Web Portal private key)
	///			- Signatures are verified using the public key associated to the private key of the entity.
	///		      that signed the message (the IDMS server certificate).
	///	
	///		  The purpose of the Signature is that <b>every entity</b> having the message is able to verify the signature inside 
	///		  and be sure of the <b>integrity</b> of the signed elements.
	///		
	///		- For Xml Encryption (X-Enc standard) :
	///			- Elements are encrypted with the public key contained in the message's recipient certificate (theIDMS server certificate).
	///			- Elements are decrypted using the private key associated to the certificate's public key (the Web Portal private key)
	///			  that was used to encrypt the elements.
	///			  
	///		  The XML elements to be encrypted are not directly encrypted with the private key of the recipient.
	///		  
	///		  Actually :
	///			- a symmetric key (called the session key) is generated
	///			- the elements are encrypted with the symmetric session key
	///			- the symmetric session key is encrypted with the private key of the recipient
	///			- the encrypted session key is appended to the message in an <code><![CDATA[<EncryptedKey>]]></code> element
	///			
	///		  To decrypt an encrypted elemment, the reipient must :
	///			- retrieve the EncryptedKey/CipherData/CipherValue element that contains the encrypted session key
	///			- decrypt the encrypted session key with his private key
	///			- finally decrypt the encrypted element, contained in the EncryptedData/CipherData/CiherValue element
	///			  
	///		  The purpose of encryption is that <b>only the targeted recipient</b> will be able to use his own private key
	///		  and decrypt the encrypted elements, hence guaranteeing the <b>confidentiality</b> of the information contained in 
	///		  the encrypted elements.
	///	
	/// </summary>
	[ComVisible(true)]
	[ClassInterface(ClassInterfaceType.None)]
	public class SOAPSigningUtility {


		/// <summary>
		/// This method fully processes CreateApplication requests :
		///		- adds required headers, signs and encrypts the  request
		///		- sends the request to the securedIDMSendpoint
		///		- decrypts the received ressponse
		///		- verifies response signatuure
		///		- if signature verification is OK removes the SOAP Header element
		/// </summary>
		/// <param name="iDMSEndpoint">The endpoint of the IDMS operation to access"http://78.155.143.145:10080/enrolmentApp_WSS/service"</param>
		/// <param name="payload">The unsecured createApplicationIn SOAP message.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encryptionCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <param name="toString">The  value of the To Ws-Addressing header.</param>
		/// <param name="actionString">The  value of the Action Ws-Addressing header.</param>
		/// <param name="replyToAddressString">The  value of the ReplyTo/Address Ws-Addressing header.</param>
		/// <param name="faultToAddressString">The  value of the FaultTo/Address Ws-Addressing header.</param>
		/// <returns>The GetApplicationStateOut response of the IDMS server, decrypted and having the SOAP header removed.</returns>
		public String ProcessCreateApplicationReq(String iDMSEndpoint, String payload, String signingPrivateKeyCertName, String encryptionCertName, String toString, String actionString, String replyToAddressString, String faultToAddressString) {

			String securedCreateApplicationRequest = SecureCreateApplicationReq(payload, signingPrivateKeyCertName, encryptionCertName, toString, actionString, replyToAddressString, faultToAddressString);
			String securedCreateApplicationResponse = SendSecureRequestToIDMS(iDMSEndpoint, securedCreateApplicationRequest);
			String createApplicationResponse = DecryptXml(securedCreateApplicationResponse);
			String createApplicationResponsePayload = removeSOAPHeader(createApplicationResponse);
			if (!VerifyXml(createApplicationResponse)) createApplicationResponsePayload = "Message Response signature not validated. Payload is " + createApplicationResponsePayload;
			return createApplicationResponsePayload;

		}


		/// <summary>
		/// This method fully processes GetApplicationState requests :
		///		- adds required headers, signs and encrypts the  request
		///		- sends the request to the securedIDMSendpoint
		///		- decrypts the received ressponse
		///		- verifies response signatuure
		///		- if  OK removes the  SOAP Header element
		/// </summary>
		/// <param name="iDMSEndpoint">The endpoint of the IDMS operation to access"http://78.155.143.145:10080/enrolmentApp_WSS/service"</param>
		/// <param name="payload">The unsecured getApplicationStateIn SOAP message.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encryptionCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <param name="toString">The  value of the To Ws-Addressing header.</param>
		/// <param name="actionString">The  value of the Action Ws-Addressing header.</param>
		/// <param name="replyToAddressString">The  value of the ReplyTo/Address Ws-Addressing header.</param>
		/// <param name="faultToAddressString">The  value of the FaultTo/Address Ws-Addressing header.</param>
		/// <returns>The GetApplicationStateOut response of the IDMS server, decrypted and having the SOAP header removed.</returns>
		public String ProcessGetApplicationStateReq(String iDMSEndpoint, String payload, String signingPrivateKeyCertName, String encryptionCertName, String toString, String actionString, String replyToAddressString, String faultToAddressString) {

			String securedGetApplicationStateRequest = SecureGetApplicationStateReq(payload, signingPrivateKeyCertName, encryptionCertName, toString, actionString, replyToAddressString, faultToAddressString);
			String securedGetApplicationStateResponse = SendSecureRequestToIDMS(securedGetApplicationStateRequest, iDMSEndpoint);
			String getApplicationStateResponse = DecryptXml(securedGetApplicationStateResponse);
			String getApplicationStateResponsePayload = "Message Response signature not validated";
			if (VerifyXml(getApplicationStateResponse)) getApplicationStateResponsePayload = removeSOAPHeader(getApplicationStateResponse);
			return getApplicationStateResponsePayload;

		}


		/// <summary>
		/// This method fully processes CreateApplication requests using default values for WS-Addressing headers:
		///		- adds required headers, signs and encrypts the  request
		///		- sends the request to the securedIDMSendpoint
		///		- decrypts the received response
		///		- verifies response signature
		///		- if signature verification is OK removes the SOAP Header element
		///		
		/// WS-Addressing default  values are : 
		/// 			String toString = "http://localhost:8085/enrolmentApp_dev/service";
		/// 			String actionString = "http://com/oberthur/idms/services/soap/enrolment/operations/IDMS2EnrolmentFacadePortType/createAppIn";
		/// 			String replyToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
		/// 			String faultToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
		/// 			
		/// </summary>
		/// <param name="iDMSEndpoint">The endpoint of the IDMS operation to access, e.g. "http://78.155.143.145:10080/enrolmentApp_WSS/service"</param>
		/// <param name="payload">The unsecured createApplicationIn SOAP message.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encryptionCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <returns>The CreateApplicationOut response of the IDMS server, decrypted and having SOAP header removed.</returns>
		public String ProcessCreateApplicationReqWithDefaultWSA(String iDMSEndpoint, String payload, String signingPrivateKeyCertName, String encryptionCertName) {

			String securedCreateApplicationRequest = SecureCreateApplicationReqWithDefaultWSA(payload, signingPrivateKeyCertName, encryptionCertName);
			String securedCreateApplicationResponse = SendSecureRequestToIDMS(iDMSEndpoint, securedCreateApplicationRequest);
			String createApplicationResponse = DecryptXml(securedCreateApplicationResponse);
			String createApplicationResponsePayload = removeSOAPHeader(createApplicationResponse);
			if (!VerifyXml(createApplicationResponse)) createApplicationResponsePayload = "Message Response signature not validated. Payload is " + createApplicationResponsePayload;
			return createApplicationResponsePayload;

		}


		/// <summary>
		/// This method fully processes GetApplicationState requests using default values for WS-Addressing headers:
		///		- adds required headers, signs and encrypts the  request
		///		- sends the request to the securedIDMSendpoint
		///		- decrypts the received ressponse
		///		- verifies response signatuure
		///		- if  OK removes the  SOAP Header element
		/// 
		/// WS-Addressing default  values are : 
		/// 			String toString = "http://localhost:8085/enrolmentApp_dev/service";
		/// 			String actionString = "http://com/oberthur/idms/services/soap/enrolment/operations/IDMS2EnrolmentFacadePortType/getApplicationStateIn";
		/// 			String replyToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
		/// 			String faultToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
		/// 			
		/// </summary>
		/// <param name="iDMSEndpoint">The endpoint of the IDMS operation to access"http://78.155.143.145:10080/enrolmentApp_WSS/service"</param>
		/// <param name="payload">The unsecured getApplicationStateIn SOAP message.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encryptionCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <returns>The CreateApplicationOut response of the IDMS server, decrypted and having SOAP header removed.</returns>
		public String ProcessGetApplicationStateReqWithDefaultWSA(String iDMSEndpoint, String payload, String signingPrivateKeyCertName, String encryptionCertName) {

			String securedGetApplicationStateRequest = SecureGetApplicationStateReqWithDefaultWSA(payload, signingPrivateKeyCertName, encryptionCertName);
			String securedGetApplicationStateResponse = SendSecureRequestToIDMS(securedGetApplicationStateRequest, iDMSEndpoint);
			String getApplicationStateResponse = DecryptXml(securedGetApplicationStateResponse);
			String getApplicationStateResponsePayload = "Message Response signature not validated";
			if (VerifyXml(getApplicationStateResponse)) getApplicationStateResponsePayload = removeSOAPHeader(getApplicationStateResponse);
			return getApplicationStateResponsePayload;

		}


		/// <summary>
		/// This method fully processes GetApplicationState requests :
		///		- adds required headers, signs and encrypts the  request
		///		- sends the request to the securedIDMSendpoint
		///		- decrypts the received ressponse
		///		- verifies response signatuure
		///		- if  OK removes the  SOAP Header element
		/// </summary>
		/// <param name="iDMSEndpoint">The endpoint of the IDMS operation to access"http://78.155.143.145:10080/enrolmentApp_WSS/service"</param>
		/// <param name="payload">The unsecured getApplicationStateIn SOAP message.</param>
		/// <param name="toString">The  value of the To Ws-Addressing header.</param>
		/// <param name="actionString">The  value of the Action Ws-Addressing header.</param>
		/// <param name="replyToAddressString">The  value of the ReplyTo/Address Ws-Addressing header.</param>
		/// <param name="faultToAddressString">The  value of the FaultTo/Address Ws-Addressing header.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encryptionCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <param name="toBeEncryptedElementLocalName">The  LocalName of the Element to be encrypted in the message.</param>
		/// <param name="toBeEncryptedElementNamespace">The  Namespace of the Element to be encrypted in the message.</param>
		/// <returns>The response of the IDMS server, decrypted and having the SOAP header removed.</returns>
		public String ProcessIDMSRequest(String iDMSEndpoint, String payload, String toString, String actionString, String replyToAddressString, String faultToAddressString, String signingPrivateKeyCertName, String encryptionCertName, String toBeEncryptedElementLocalName, String toBeEncryptedElementNamespace) {

			String securedGenericIDMSRequest = SecureIDMSRequest(payload, toString, actionString, replyToAddressString, faultToAddressString, signingPrivateKeyCertName, encryptionCertName, toBeEncryptedElementLocalName, toBeEncryptedElementNamespace);
			String securedGenericIDMSResponse = SendSecureRequestToIDMS(securedGenericIDMSRequest, iDMSEndpoint);
			String getGenericIDMSResponse = DecryptXml(securedGenericIDMSResponse);
			String getGenericIDMSResponsePayload = "Message Response signature not validated";
			if (VerifyXml(getGenericIDMSResponse)) getGenericIDMSResponsePayload = removeSOAPHeader(getGenericIDMSResponse);
			return getGenericIDMSResponsePayload;

		}


		/// <summary>
		/// This method signs and encrypts the provided createApplication request, given certificates names and using default values for required WS-Addressing informations.
		/// The encrypted element will be {http://com/oberthur/idms/services/soap/enrolment/definitions}createApplicationIn (first child of the SOAP Body).
		/// 
		/// WS-Addressing default  values are : 
		/// 			String toString = "http://localhost:8085/enrolmentApp_dev/service";
		/// 			String actionString = "http://com/oberthur/idms/services/soap/enrolment/operations/IDMS2EnrolmentFacadePortType/createAppIn";
		/// 			String replyToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
		/// 			String faultToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn SOAP message.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encryptionCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <returns>The secured (timestamped, signed and encrypted) createApplicationIn SOAP request that can then be sent as is to the IDMS server.</returns>
		[ComVisible(true)]
		public String SecureCreateApplicationReqWithDefaultWSA(String payload, String signingPrivateKeyCertName, String encryptionCertName) {

			String toString = "http://localhost:8085/enrolmentApp_dev/service";
			String actionString = "http://com/oberthur/idms/services/soap/enrolment/operations/IDMS2EnrolmentFacadePortType/createAppIn";
			String replyToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
			String faultToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
			payload = AddAdressingHeaders(payload, toString, actionString, replyToAddressString, faultToAddressString);
			payload = AddTimestampSecurityHeader(payload);
			payload = SignXml(payload, signingPrivateKeyCertName);
			return EncryptXml(payload, encryptionCertName, "createApplicationIn", "http://com/oberthur/idms/services/soap/enrolment/definitions");

		}


		/// <summary>
		/// This method signs and encrypts the provided createApplication request, given certificates names and required WS-Addressing informations.
		/// The encrypted element will be {http://com/oberthur/idms/services/soap/enrolment/definitions}createApplicationIn (first child of the SOAP Body).
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn SOAP message.</param>
		/// <param name="toString">The  value of the To Ws-Addressing header.</param>
		/// <param name="actionString">The  value of the Action Ws-Addressing header.</param>
		/// <param name="replyToAddressString">The  value of the ReplyTo/Address Ws-Addressing header.</param>
		/// <param name="faultToAddressString">The  value of the FaultTo/Address Ws-Addressing header.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encryptionCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <returns>The secured (timestamped, signed and encrypted) createApplicationIn SOAP request that can then be sent as is to the IDMS server.</returns>
		[ComVisible(true)]
		public String SecureCreateApplicationReq(String payload, String toString, String actionString, String replyToAddressString, String faultToAddressString, String signingPrivateKeyCertName, String encryptionCertName) {

			payload = AddAdressingHeaders(payload, toString, actionString, replyToAddressString, faultToAddressString);
			payload = AddTimestampSecurityHeader(payload);
			payload = SignXml(payload, signingPrivateKeyCertName);
			return EncryptXml(payload, encryptionCertName, "createApplicationIn", "http://com/oberthur/idms/services/soap/enrolment/definitions");

		}


		/// <summary>
		/// This method signs and encrypts the provided getApplicationState request, given certificates names and using default values for required WS-Addressing informations.
		/// The encrypted element will be {http://com/oberthur/idms/services/soap/enrolment/definitions}getApplicationStateIn (first child of the SOAP Body).
		/// 
		/// WS-Addressing default  values are : 
		/// 			String toString = "http://localhost:8085/enrolmentApp_dev/service";
		/// 			String actionString = "http://com/oberthur/idms/services/soap/enrolment/operations/IDMS2EnrolmentFacadePortType/getApplicationStateIn";
		/// 			String replyToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
		/// 			String faultToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
		/// </summary>
		/// <param name="payload">The unsecured getApplicationStateIn SOAP message.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encryptionCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <returns>The secured (timestamped, signed and encrypted) createApplicationIn SOAP request that can then be sent as is to the IDMS server.</returns>
		[ComVisible(true)]
		public String SecureGetApplicationStateReqWithDefaultWSA(String payload, String signingPrivateKeyCertName, String encryptionCertName) {

			String toString = "http://localhost:8085/enrolmentApp_dev/service";
			String actionString = "http://com/oberthur/idms/services/soap/enrolment/operations/IDMS2EnrolmentFacadePortType/getApplicationStateIn";
			String replyToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
			String faultToAddressString = "http://www.w3.org/2005/08/addressing/anonymous";
			payload = AddAdressingHeaders(payload, toString, actionString, replyToAddressString, faultToAddressString);
			payload = AddTimestampSecurityHeader(payload);
			payload = SignXml(payload, signingPrivateKeyCertName);
			return EncryptXml(payload, encryptionCertName, "getApplicationStateIn", "http://com/oberthur/idms/services/soap/enrolment/definitions");

		}

		/// <summary>
		/// This method signs and encrypts the provided getApplicationState request, given certificates names and required WS-Addressing informations
		/// The encrypted element will be {http://com/oberthur/idms/services/soap/enrolment/definitions}getApplicationStateIn (first child of the SOAP Body).
		/// </summary>
		/// <param name="payload">The unsecured getApplicationStateIn SOAP message.</param>
		/// <param name="toString">The  value of the To Ws-Addressing header.</param>
		/// <param name="actionString">The  value of the Action Ws-Addressing header.</param>
		/// <param name="replyToAddressString">The  value of the ReplyTo/Address Ws-Addressing header.</param>
		/// <param name="faultToAddressString">The  value of the FaultTo/Address Ws-Addressing header.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encryptionCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <returns>The secured (timestamped, signed and encrypted) createApplicationIn SOAP request that can then be sent as is to the IDMS server.</returns>
		[ComVisible(true)]
		public String SecureGetApplicationStateReq(String payload, String toString, String actionString, String replyToAddressString, String faultToAddressString, String signingPrivateKeyCertName, String encryptionCertName) {

			payload = AddAdressingHeaders(payload, toString, actionString, replyToAddressString, faultToAddressString);
			payload = AddTimestampSecurityHeader(payload);
			payload = SignXml(payload, signingPrivateKeyCertName);
			return EncryptXml(payload, encryptionCertName, "getApplicationStateIn", "http://com/oberthur/idms/services/soap/enrolment/definitions");

		}

		/// <summary>
		/// This method signs and encrypts the provided createApplication request, given certificates names and required WS-Addressing informations.
		/// The encrypted element will be {http://com/oberthur/idms/services/soap/enrolment/definitions}createApplicationIn (first child of the SOAP Body).
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn SOAP message.</param>
		/// <param name="toString">The  value of the To Ws-Addressing header.</param>
		/// <param name="actionString">The  value of the Action Ws-Addressing header.</param>
		/// <param name="replyToAddressString">The  value of the ReplyTo/Address Ws-Addressing header.</param>
		/// <param name="faultToAddressString">The  value of the FaultTo/Address Ws-Addressing header.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encryptionCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <param name="toBeEncryptedElementLocalName">The  LocalName of the Element to be encrypted in the message.</param>
		/// <param name="toBeEncryptedElementNamespace">The  Namespace of the Element to be encrypted in the message.</param>
		/// <returns>The secured (timestamped, signed and encrypted) createApplicationIn SOAP request that can then be sent as is to the IDMS server.</returns>
		[ComVisible(true)]
		public String SecureIDMSRequest(String payload, String toString, String actionString, String replyToAddressString, String faultToAddressString, String signingPrivateKeyCertName, String encryptionCertName, String toBeEncryptedElementLocalName, String toBeEncryptedElementNamespace) {

			payload = AddAdressingHeaders(payload, toString, actionString, replyToAddressString, faultToAddressString);
			payload = AddTimestampSecurityHeader(payload);
			payload = SignXml(payload, signingPrivateKeyCertName);
			return EncryptXml(payload, encryptionCertName, toBeEncryptedElementLocalName, toBeEncryptedElementNamespace);

		}


		/// <summary>
		/// Utility method sending the secure IDMS request to the IDMS server
		/// </summary>
		/// <param name="securedRequest">The String containing the SOAP request to IDMS</param>
		/// <param name="iDMSEndpoint">The endpoint of the IDMS operation to access"http://78.155.143.145:10080/enrolmentApp_WSS/service"</param>
		/// <returns>A Strig containing theIDMS server response</returns>
		public String SendSecureRequestToIDMS(String iDMSEndpoint, String securedRequest) {

			HttpWebRequest httpRequest = (HttpWebRequest) WebRequest.Create(iDMSEndpoint);
			byte[] data = Encoding.ASCII.GetBytes(securedRequest);
			httpRequest.Method = "POST";
			httpRequest.ContentType = "application/soap+xml";
			httpRequest.ContentLength = data.Length;
			using (Stream stream = httpRequest.GetRequestStream()) {
				stream.Write(data, 0, data.Length);
			}
			HttpWebResponse httpResponse = (HttpWebResponse)httpRequest.GetResponse();
			return new StreamReader(httpResponse.GetResponseStream()).ReadToEnd();

		}


		/// <summary>
		/// Utility method sending the secure IDMS request to the IDMS server over TLS, using mutual SSL Authentication.
		/// </summary>
		/// <param name="iDMSEndpoint">The endpoint of the IDMS operation to access"http://78.155.143.145:10080/enrolmentApp_WSS/service"</param>
		/// <param name="certName">A discriminant part of the DN of the certificate to be retrieved (e.g. 'CN=IDMSClient' or 'IDMSClient').</param>
		/// <param name="securedRequest">The String containing the SOAP request to IDMS</param>
		/// <returns>A Strig containing theIDMS server response</returns>
		public String SendSecureRequestToIDMSOverTLSMutual(String iDMSEndpoint, String certName, String securedRequest) {

			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
			HttpWebRequest httpRequest = (HttpWebRequest)WebRequest.Create(iDMSEndpoint);
			X509Certificate2 certificate = GetCertificate(certName);
			httpRequest.ClientCertificates.Add(certificate);
			httpRequest.PreAuthenticate = true;
			byte[] data = Encoding.ASCII.GetBytes(securedRequest);
			httpRequest.Method = "POST";
			httpRequest.ContentType = "application/soap+xml";
			httpRequest.ContentLength = data.Length;
			using (Stream stream = httpRequest.GetRequestStream()) {
				stream.Write(data, 0, data.Length);
			}
			HttpWebResponse httpResponse = (HttpWebResponse)httpRequest.GetResponse();
			return new StreamReader(httpResponse.GetResponseStream()).ReadToEnd();

		}


		/// <summary>
		/// Utility method returning the X509Certificate2 object in the LocalMachine Windows Certificate Store matching the provided certName.
		/// </summary>
		/// <param name="certName">A discriminant part of the DN of the certificate to be retrieved (e.g. 'CN=IDMSClient' or 'IDMSClient').</param>
		/// <returns>The X509Certificate2 object in the LocalMachine Windows Certificate Store matching the provided certName.</returns>
		[ComVisible(true)]
		public X509Certificate2 GetCertificate(String certName) {

			X509Store my = new X509Store(StoreName.My, StoreLocation.LocalMachine);
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


		/// <summary>
		/// Utility method returning the X509Certificate2 object in the LocalMachine Windows Certificate Store matching the provided certName.
		/// </summary>
		/// <param name="issuer">The DN of the issuing Authority</param>
		/// <param name="serial">The serial number of the certificate to be retrieved</param>
		/// <returns>The X509Certificate2 object in the LocalMachine Windows Certificate Store issued by the provided Authority and having the provided SerialNumber</returns>
		[ComVisible(true)]
		public X509Certificate2 GetCertificateByIssuerSerial(String issuer, String serial) {

			X509Store my = new X509Store(StoreName.My, StoreLocation.LocalMachine);
			my.Open(OpenFlags.ReadOnly);
			X509Certificate2 signingCert = null;
			long serialInt = long.Parse(serial);
			foreach (X509Certificate2 cert in my.Certificates) {
				// Windows bug : certificates with DN like 
				//		CN =SUNCA, OU=JWS, O=SUN, ST=Some-State, C=AU 
				// are registered as 
				//		CN =SUNCA, OU=JWS, O=SUN, S=Some-State, C=AU
				// So we need to rewrite 'S=' or 'ST=' to 'STATE=' to compare issuers... Need to do cert DN C14N here!!
				String realIssuer = cert.Issuer.Replace("S=", "ST=").Replace("ST=", "STATE=");
				issuer = issuer.Replace("S=", "ST=").Replace("ST=", "STATE=");
				long certSerialInt = 0;
				try {
					certSerialInt = long.Parse(cert.SerialNumber);
				} catch (Exception e) {
					CryptographicException ce = new CryptographicException("Badly formatted cert in store. SerialNumber is not an INTEGER as per the rfc2459, found : " + cert.SerialNumber +  "\n" + e.Message + "\n" + e.StackTrace);
					throw ce;
				}
				if (serialInt.Equals(certSerialInt)) {
					if (issuer.Equals(realIssuer)) {
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


		/// <summary>
		/// Utility method adding the required (as per the WS-Policy fragment in the IDMSEnrolmentFacade WSDL) WS-Addressing headers 
		/// (To, Action, ReplyTo and FaultTo) to the SOAP Header of a createApplication or getApplicationState unsecured SOAP request.
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn or getApplicationState unsecured SOAP request.</param>
		/// <param name="toString">The  value of the To Ws-Addressing header.</param>
		/// <param name="actionString">The  value of the Action Ws-Addressing header.</param>
		/// <param name="replyToAddressString">The  value of the ReplyTo/Address Ws-Addressing header.</param>
		/// <param name="faultToAddressString">The  value of the FaultTo/Address Ws-Addressing header.</param>
		/// <returns>The createApplication or getApplicationState SOAP request containing required WS-Addressing headers in the SOAP Header.</returns>
		[ComVisible(true)]
		public String AddAdressingHeaders(String payload, String toString, String actionString, String replyToAddressString, String faultToAddressString) {

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
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
			toNode.InnerText = toString;
			headerNode.AppendChild(toNode);

			XmlElement actionNode = xmlDoc.CreateElement("wsa", "Action", "http://www.w3.org/2005/08/addressing");
			actionNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_3");
			actionNode.SetAttribute("mustUnderstand", "http://www.w3.org/2003/05/soap-envelope", "true");
			actionNode.InnerText = actionString;
			headerNode.AppendChild(actionNode);

			XmlElement replyToNode = xmlDoc.CreateElement("wsa", "ReplyTo", "http://www.w3.org/2005/08/addressing");
			replyToNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_4");
			XmlElement replyToAddressNode = xmlDoc.CreateElement("wsa", "Address", "http://www.w3.org/2005/08/addressing");
			replyToAddressNode.InnerText = replyToAddressString;
			replyToNode.AppendChild(replyToAddressNode);
			headerNode.AppendChild(replyToNode);

			XmlElement faultToNode = xmlDoc.CreateElement("wsa", "FaultTo", "http://www.w3.org/2005/08/addressing");
			faultToNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_5");
			XmlElement faultToAddressNode = xmlDoc.CreateElement("wsa", "Address", "http://www.w3.org/2005/08/addressing");
			faultToAddressNode.InnerText = faultToAddressString;
			faultToNode.AppendChild(faultToAddressNode);
			headerNode.AppendChild(faultToNode);

			XmlElement messageIDNode = xmlDoc.CreateElement("wsa", "MessageID", "http://www.w3.org/2005/08/addressing");
			messageIDNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_6");
			messageIDNode.InnerText = "uuid:" + Guid.NewGuid().ToString();
			headerNode.AppendChild(messageIDNode);

			return xmlDoc.InnerXml;

		}


		/// <summary>
		/// Utility method adding the required wsu:Timestamp element (as per the WS-Policy fragment in the IDMSEnrolmentFacade WSDL) 
		/// to the wsse:Security Header of a createApplication or getApplicationState unsecured SOAP request.
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn or getApplicationState unsecured SOAP request.</param>
		/// <returns>The createApplication or getApplicationState SOAP request containing required Timestamp in the WS-Security /S:Envelope/S:Header/wsse:Security header.</returns>
		[ComVisible(true)]
		public String AddTimestampSecurityHeader(String payload) {

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
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

		/// <summary>
		/// Utility method signing the createApplicationIn or getApplicationState unsecured SOAP request.
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn or getApplicationState unsecured SOAP request.</param>
		/// <param name="signingPrivateKeyCertName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <returns>The createApplicationIn or getApplicationState SOAP request signed as expected by the IDMS server.</returns>
		[ComVisible(true)]
		public String SignXml(String payload, String signingPrivateKeyCertName) {

			if (payload == null)
				throw new ArgumentException("xmlString");
			if (signingPrivateKeyCertName == null)
				throw new ArgumentException("signingCertName");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
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
			return xmlDoc.InnerXml;

		}


		/// <summary>
		/// Utility method verifing the signature of a SOAP message received from IDMS using a pinned public key.
		/// </summary>
		/// <param name="payload">The signed SOAP message received from IDMS.</param>
		/// <param name="signingVerificationCertName">A discriminant part of the DN of the certificate that must be used to verify the signature of the message.</param>
		/// <returns>A Boolean, true if signature verifies, false if not.</returns>
		// Verify the signature of an XML file against an asymmetric algorithm and return the result.
		[ComVisible(true)]
		public Boolean VerifyXmlWithCertName(String payload, String signingVerificationCertName) {

			if (payload == null)
				throw new ArgumentException("xmlString");
			if (signingVerificationCertName == null)
				throw new ArgumentException("signingCert");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("e", "http://www.w3.org/2001/04/xmlenc#");
			ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
			ns.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			XmlElement SignatureNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/ds:Signature", ns) as XmlElement;

			X509Certificate2 signingCert = GetCertificate(signingVerificationCertName);
			SignedXmlWithId signedXml = new SignedXmlWithId(xmlDoc);
			// signedXml.SigningKey
			signedXml.LoadXml(SignatureNode);
			//return signedXml.CheckSignature(signedXml.SigningKey);
			return signedXml.CheckSignature((RSACryptoServiceProvider)signingCert.PublicKey.Key);

		}


		/// <summary>
		/// Utility method verifying the signature of a SOAP message received from IDMS, retrieving the certificate's 
		/// public key that must be used to verify the signature of the message dynamically.
		/// </summary>
		/// <param name="payload">The signed SOAP message received from IDMS.</param>
		/// <returns>A Boolean, true if signature verifies, false if not.</returns>
		// Verify the signature of an XML file against an asymmetric algorithm and return the result.
		[ComVisible(true)]
		public Boolean VerifyXml(String payload) {

			if (payload == null)
				throw new ArgumentException("xmlString");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);

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


		/// <summary>
		/// Utility method encrypting the unencrypted SOAP message to be sent to IDMS.
		/// 
		/// Due to format incompatibility between .Net and Java stacks we first need to reformat the message
		/// after encryption so that IDMS is able to decrypt it.
		/// 
		///  Basically, the EncryptedKey block generated by.Net is in /S:Envelope/S:Body/e:EncryptdData/ds:KeyInfo under this format : 
		///  <code>
		///  <![CDATA[
		/// 	<ds:KeyInfo>
		///  		<xenc:EncryptedKey
		///				xmlns:ns17= "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512"
		///				xmlns:ns16= "http://schemas.xmlsoap.org/soap/envelope/"
		///				Id = "_5007" >
		///           <xenc:EncryptionMethod Algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
		///           <ds:KeyInfo>
		///  				<ds:X509Data>
		///  					<ds:X509IssuerSerial>
		///  						<ds:X509IssuerName>CN= SUNCA, OU= JWS, O= SUN, ST= Some - State, C= AU </ds:X509IssuerName>
		///  						<ds:X509SerialNumber>2</ds:X509SerialNumber>
		///  					</ds:X509IssuerSerial>
		///  				</ds:X509Data>
		///  			</ds:KeyInfo>
		///  			<xenc:CipherData>
		///  				<xenc:CipherValue>c6DN7B.....O/BATrcM=</xenc:CipherValue>
		///  			</xenc:CipherData>
		///  			<xenc:ReferenceList>
		///  				<xenc:DataReference URI = "#_payload" />
		///           </xenc:ReferenceList>
		///  		</xenc:EncryptedKey>
		///  	</ds:KeyInfo>
		///  ]]>
		///  </code>
		///  	
		///  IDMS waits for the EncryptedKey block in /S:Envelope/S:Header/wsse:/Security and in the following format :
		///  	
		/// <code>
		/// <![CDATA[
		///  	<xenc:EncryptedKey Id = "_5007" >
		///       <xenc:EncryptionMethod Algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
		///       <ds:KeyInfo xmlns:xsi= "http://www.w3.org/2001/XMLSchema-instance" xsi:type= "KeyInfoType" >
		///           <wsse:SecurityTokenReference>
		///  				<ds:X509Data>
		///  					<ds:X509IssuerSerial>
		///  						<ds:X509IssuerName>CN= SUNCA, OU= JWS, O= SUN, ST= Some - State, C= AU </ds:X509IssuerName>
		///  						<ds:X509SerialNumber>2</ds:X509SerialNumber>
		///  					</ds:X509IssuerSerial>
		///  				</ds:X509Data>
		///  			</wsse:SecurityTokenReference>
		///  		</ds:KeyInfo>
		///  		<xenc:CipherData>
		///  			<xenc:CipherValue>Ah1EDF.....+AchU=</xenc:CipherValue>
		///  		</xenc:CipherData>
		///  		<xenc:ReferenceList>
		///  			<xenc:DataReference URI = "#_payload" />
		///       </xenc:ReferenceList>
		///  	</xenc:EncryptedKey>
		///  ]]>
		///  </code>
		/// 
		/// </summary>
		/// <param name="payload">The unencrypted SOAP message to encrypt.</param>
		/// <param name="encryptionCertificateName">A discriminant part of the DN of the certificate that must be used to encrypt the SOAP message.</param>
		/// <param name="elementToEncryptLocalName">The LocalName of the to-be-encrypted element.</param>
		/// <param name="elementToEncryptNamespace">The Namespace of the to-be-encrypted element.</param>
		/// <returns>The SOAP message, encrypted.</returns>
		[ComVisible(true)]
		public String EncryptXml(String payload, String encryptionCertificateName, string elementToEncryptLocalName, string elementToEncryptNamespace) {

			if (payload == null)
				throw new ArgumentNullException("xmlString");
			if (elementToEncryptLocalName == null)
				throw new ArgumentNullException("ElementToEncryptName");
			if (encryptionCertificateName == null)
				throw new ArgumentNullException("signingCertName");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);

			XmlElement elementToEncrypt = null;
			if (elementToEncryptNamespace == null) {
				elementToEncrypt = xmlDoc.GetElementsByTagName(elementToEncryptLocalName)[0] as XmlElement;
			} else {
				elementToEncrypt = xmlDoc.GetElementsByTagName(elementToEncryptLocalName, elementToEncryptNamespace)[0] as XmlElement;
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
			X509Certificate2 EncryptionCertificate = GetCertificate(encryptionCertificateName);
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

			try {
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
				CryptographicException ce = new CryptographicException("An exception was raised while trying to encrypt the message.\n" + e.Message + "\n" + e.StackTrace);
				throw ce;
			}
			return xmlDoc.InnerXml;

		}


		/// <summary>
		/// Utility method decrypting the content of the EncryptedData nodes in the document, pinning the private Key  to be used to decrypt.
		/// </summary>
		/// <param name="payload">The encrypted SOAP message to decrypt.</param>
		/// <param name="decryptingPrivateKeyCertName">The pinnedprivaye key to be used for decryption.</param>
		/// <returns>The decrypted SOAP message.</returns>
		[ComVisible(true)]
		public String DecryptXmlWithPrivKeyCertName(String payload, string decryptingPrivateKeyCertName) {

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			X509Certificate2 signingCert = GetCertificate(decryptingPrivateKeyCertName);

			EncryptedXml exml = new EncryptedXml(xmlDoc);
			exml.AddKeyNameMapping(signingCert.FriendlyName, (RSA)signingCert.PrivateKey);
			try {
				exml.DecryptDocument();
			} catch (Exception e) {
				CryptographicException ce = new CryptographicException("An exception was raised while trying to decrypt the message.\n" + e.Message + "\n" + e.StackTrace);
				throw ce;
			}
			return xmlDoc.InnerXml;

		}


		/// <summary>
		/// Utility method decrypting the content of the EncryptedData nodes in the document, using a dynamically retrieved private Key to decrypt.
		/// 
		/// Due to format incompatibility between .Net and Java stacks we first need to reformat the message
		/// encrypted by IDMS so that the .Net stack is able to decrypt it.
		///   
		/// The EncryptedKey block sent by IDMS is in /S:Envelope/S:Header/wsse:/Security and in the following format :
		///   
		///  <code>
		///  <![CDATA[
		///   	<xenc:EncryptedKey Id = "_5007">
		///        <xenc:EncryptionMethod Algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
		///        <ds:KeyInfo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="KeyInfoType">
		///   			<wsse:SecurityTokenReference>
		///   				<ds:X509Data>
		///   					<ds:X509IssuerSerial>
		///   						<ds:X509IssuerName>CN=SUNCA, OU=JWS, O=SUN, ST=Some-State, C=AU</ds:X509IssuerName>
		///   						<ds:X509SerialNumber>3</ds:X509SerialNumber>
		///   					</ds:X509IssuerSerial>
		///   				</ds:X509Data>
		///   			</wsse:SecurityTokenReference>
		///   		</ds:KeyInfo>
		///   		<xenc:CipherData>
		///   			<xenc:CipherValue>Ah1EDF.....+AchU=</xenc:CipherValue>
		///   		</xenc:CipherData>
		///   		<xenc:ReferenceList>
		///   			<xenc:DataReference URI = "#_5008" />
		///        </xenc:ReferenceList>
		///   	</xenc:EncryptedKey>
		///  ]]>
		///  </code>
		///   	
		/// As.Net doesn't support the ReferenceList/DataReference method to reference symmetric EncryptedKeys that 
		/// must be used to decrypt EncryptedData elements we must reformat the message to put the EncryptedKey 
		/// where .Net will be able to retrieve it, namely in /S:Envelope/S:Body/e:EncryptdData/ds:KeyInfo, 
		/// and under this format : 
		///   	
		///  <code>
		///  <![CDATA[
		///   	<ds:KeyInfo>
		///   		<xenc:EncryptedKey
		///				  xmlns:ns17= "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512"
		///				  xmlns:ns16= "http://schemas.xmlsoap.org/soap/envelope/"
		///				  Id = "_5007" >
		///            <xenc:EncryptionMethod Algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
		///            <ds:KeyInfo>
		///   				<ds:KeyName>CN= xwssecurityclient, OU= SUN, O= Internet Widgits Pty Ltd, ST= Some - State, C= AU </ds:KeyName>
		///   			</ds:KeyInfo>
		///   			<xenc:CipherData>
		///   				<xenc:CipherValue>c6DN7B.....O/BATrcM=</xenc:CipherValue>
		///   			</xenc:CipherData>
		///   			<xenc:ReferenceList>
		///   				<xenc:DataReference URI = "#_5008" />
		///            </xenc:ReferenceList>
		///   		</xenc:EncryptedKey>
		///   	</ds:KeyInfo>
		///  ]]>
		///  </code>
		///   	
		///   	Note that we don't use X509Data to reference the asymmetric EncryptedKey that was used to decrypt
		///   	the symmetric EncryptedKey because of the difference in the representation of the State RDN (S in Java and 
		///   	ST in Microsoft) in the Certificates DN, and the.Net stack is not able to retrieve the Certificate from the 
		///   	Issuer DN provided by the Glassfish/Metro stack.
		///   	We use KeyName instead. 
		/// 
		/// </summary>
		/// <param name="payload">The unencrypted SOAP message to encrypt.</param>
		/// <returns>The decrypted SOAP message.</returns>
		[ComVisible(true)]
		public string DecryptXml(String payload) {

			if (payload == null)
				throw new ArgumentNullException("xmlString");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);

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

				EncryptedXml exml = new EncryptedXml(xmlDoc);
				exml.AddKeyNameMapping(KeyNameString, (RSA)cert.PrivateKey);
				exml.DecryptDocument();
				//exml.DecryptData(encData, exml.GetDecryptionKey(encData, "http://www.w3.org/2001/04/xmlenc#aes128-cbc"));
			} catch (Exception e) {
				CryptographicException ce = new CryptographicException("An exception was raised while trying to decrypt the message.\n" + e.Message + "\n" + e.StackTrace);
				throw ce;
			}
			return xmlDoc.InnerXml;

		}


		/// <summary>
		/// Removes SOAP Header so that it will be easier for the ASP scripts to work with the message
		/// </summary>
		/// <param name="payload">The SOAP message from which we want to remove the Header.</param>
		/// <returns>The SOAP message without Header</returns>
		public String removeSOAPHeader(String payload) {

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			XmlElement envelopeNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope", ns) as XmlElement;
			XmlElement headerNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header", ns) as XmlElement;
			envelopeNode.RemoveChild(headerNode);
			return xmlDoc.InnerXml;

		}

		/// <summary>
		/// Utility method setting the SOAP Body element Id attribute value to '_1'
		/// </summary>
		/// <param name="payload">The SOAP message to be modified.</param>
		/// <returns>The same SOAP message with a S:Body element having its wsu:Id attribute set to '_1'</returns>
		public String SetSOAPBodyIDAttribute(String payload) {
			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			XmlElement envelopeNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope", ns) as XmlElement;
			XmlElement bodyNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body", ns) as XmlElement;
			if (bodyNode.HasAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"))
				bodyNode.RemoveAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			bodyNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_1");
			return xmlDoc.InnerXml;

		}


	}


	/// <summary>
	/// Utility class overriding the GetIdElement method of SignedXml class to allow for finding elements by Id attribute.
	/// defined in http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd
	/// </summary>
	[ComVisible(true)]
	public class SignedXmlWithId : SignedXml {

		/// <summary>
		/// Inherited constructor from SignedXml.
		/// </summary>
		/// <param name="xml">The XML Document</param>

		public SignedXmlWithId(XmlDocument xml) : base(xml) { }
		/// <summary>
		/// Inherited constructor from SignedXml.
		/// </summary>
		/// <param name="xmlElement">The XML Element</param>

		public SignedXmlWithId(XmlElement xmlElement) : base(xmlElement) { }
		/// <summary>
		/// Overriden GetIdElement(XmlDocument doc, string id) method allowing for finding elements by Id attribute.
		/// </summary>
		/// <param name="doc">The XML document.</param>
		/// <param name="id">The Id attribute of the element  to be retrieved.</param>
		/// <returns>The XmlElement which has the provided Id attribute.</returns>

		public override XmlElement GetIdElement(XmlDocument doc, string id) {
			// check to see if it's a standard ID reference
			XmlElement idElem = base.GetIdElement(doc, id);
			if (idElem == null) {
				XmlNamespaceManager nsManager = new XmlNamespaceManager(doc.NameTable);
				nsManager.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
				idElem = doc.SelectSingleNode("//*[@wsu:Id=\"" + id + "\"]", nsManager) as XmlElement;
			}
			return idElem;
		}

	}


	/// <summary>
	/// Utility class overriding the GetXml method of the KeyInfoClause class allowing for the building of KeyInfo/SecurityTokenReference/Reference block.
	/// </summary>
	[ComVisible(true)]
	public class SecurityTokenReference : KeyInfoClause {

		/// <summary>
		/// Accessor to the BinarySecurityTokenId attribute.
		/// </summary>
		public string BinarySecurityTokenId { get; set; }

		/// <summary>
		/// getter/setter for the BinarySecurityTokenId attribute.
		/// </summary>
		/// <param name="binarySecurityTokenId">the BinarySecurityTokenId</param>
		public SecurityTokenReference(string binarySecurityTokenId) {
			this.BinarySecurityTokenId = binarySecurityTokenId;
		}

		/// <summary>
		/// Overriden GetXml() method retrieveing the SecurityTokenReference element XML content.
		/// </summary>
		/// <returns></returns>
		public override XmlElement GetXml() {
			XmlDocument doc = new XmlDocument();
			XmlElement strXmlElement = doc.CreateElement("wse", "SecurityTokenReference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			doc.AppendChild(strXmlElement);
			XmlElement reference = doc.CreateElement("wse", "Reference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			reference.SetAttribute("URI", "#" + BinarySecurityTokenId);
			reference.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
			strXmlElement.AppendChild(reference);
			return strXmlElement;
		}

		/// <summary>
		/// Overriden LoadXml(XmlElement element) method preventing from writing manually the content of the SecurityTokenReference element XML content.
		/// </summary>
		/// <param name="element"></param>
		public override void LoadXml(XmlElement element) {
			throw new NotImplementedException();
		}

	}

}
