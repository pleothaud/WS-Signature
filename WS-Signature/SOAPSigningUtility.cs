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
	using System.Collections.Generic;

	/// <summary>
	/// Utility Class to sign/verify and encrypt/decrypt the messages exchanged with the IDMS server.
	/// 
	/// As a reminder, when using certificates based, asymmetric, cryptography :
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
	///		  To decrypt an encrypted element, the recipient must :
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
		/// This method fully processes generic IDMS requests :
		///		- Adds required headers, signs and encrypts the request,
		///		- Sends the request to the securedIDMSendpoint,
		/// 	- Verifies that the current date and time of the IDMS response is between the incoming message Timestamp Creates and Expires date times,
		///		- Decrypts the received response,
		///		- Verifies response signature and
		///		- If OK removes the  SOAP Header element.
		/// This method will throw a CryptographicException if the current date and time of the IDMS response is not between the 
		/// incoming message Timestamp Creates and Expires date times, or if the Signature of the IDMS response is not valid.
		/// </summary>
		/// <param name="iDMSEndpoint">The endpoint of the IDMS operation to access"http://78.155.143.145:10080/enrolmentApp_WSS/service"</param>
		/// <param name="payload">The unsecured getApplicationStateIn SOAP message.</param>
		/// <param name="to">The  value of the 'To' WS-Addressing header.</param>
		/// <param name="action">The  value of the 'Action' WS-Addressing header.</param>
		/// <param name="replyTo">The  value of the 'ReplyTo/Address' WS-Addressing header.</param>
		/// <param name="faultTo">The  value of the 'FaultTo/Address' WS-Addressing header.</param>
		/// <param name="sigPrivKeyName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <returns>The response of the IDMS server, decrypted and having the SOAP header removed.</returns>
		public String ProcessRequestToIDMS(
					String iDMSEndpoint,
					String payload,
					String sigPrivKeyName,
					String encCertName,
					String to,
					String action,
					String replyTo,
					String faultTo) {

			if (iDMSEndpoint == null)
				throw new ArgumentException("ProcessRequestToIDMS: iDMSEndpoint cannot be null");
			if (payload == null)
				throw new ArgumentException("ProcessRequestToIDMS: payload cannot be null");
			if (sigPrivKeyName == null)
				throw new ArgumentException("ProcessRequestToIDMS: sigPrivKeyName cannot be null");
			if (encCertName == null)
				throw new ArgumentException("ProcessRequestToIDMS: encCertName cannot be null");
			if (to == null)
				throw new ArgumentException("ProcessRequestToIDMS: to cannot be null");
			if (action == null)
				throw new ArgumentException("ProcessRequestToIDMS: action cannot be null");
			if (replyTo == null)
				throw new ArgumentException("ProcessRequestToIDMS: replyTo cannot be null");
			if (faultTo == null)
				throw new ArgumentException("ProcessRequestToIDMS: faultTo cannot be null");

			String securedGenericRequestToIDMS = SecureRequestToIDMS(payload, to, action, replyTo, faultTo, sigPrivKeyName, encCertName);
			String securedGenericResponseToIDMS = SendRequestToIDMS(iDMSEndpoint, securedGenericRequestToIDMS);
			if (!CheckTSValidity(securedGenericResponseToIDMS))
				throw new CryptographicException("Current DateTime not beween the Timesatmp Created and Expires Date Times.\nIncoming request was:\n" + payload);
			String genericIDMSResponse = DecryptXml(securedGenericResponseToIDMS);
			if (!VerifyXml(genericIDMSResponse))
				throw new CryptographicException("Response message signature does not validate. Response was:\n " + genericIDMSResponse);
			String genericIDMSResponsePayload = removeSOAPHeader(genericIDMSResponse);

			return genericIDMSResponsePayload;

		}

		/// <summary>
		/// This method fully processes GetApplicationState requests :
		///		- Adds required headers, signs and encrypts the request,
		///		- Sends the request to the securedIDMSendpoint,
		/// 	- Verifies that the current date and time of the IDMS response is between the incoming message Timestamp Creates and Expires date times,
		///		- Decrypts the received response,
		///		- Verifies response signature and
		///		- If OK removes the  SOAP Header element.
		/// This method will throw a CryptographicException if the current date and time of the IDMS response is not between the 
		/// incoming message Timestamp Creates and Expires date times, or if the Signature of the IDMS response is not valid.
		/// </summary>
		/// <param name="iDMSEndpoint">The endpoint of the IDMS operation to access"http://78.155.143.145:10080/enrolmentApp_WSS/service"</param>
		/// <param name="tLSClientCertName">A discriminant part of the DN of the certificate associated to the private key to be used to establish 
		/// the mutually authenticated TLS tunnel. (e.g. 'CN=WebPortalClientCert' or 'WebPortalClientCert').</param>
		/// <param name="payload">The unsecured getApplicationStateIn SOAP message.</param>
		/// <param name="to">The value of the 'To' WS-Addressing header.</param>
		/// <param name="action">The value of the 'Action' WS-Addressing header.</param>
		/// <param name="replyTo">The value of the 'ReplyTo/Address' WS-Addressing header.</param>
		/// <param name="faultTo">The value of the 'FaultTo/Address' WS-Addressing header.</param>
		/// <param name="sigPrivKeyName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <returns>The response of the IDMS server, decrypted and having the SOAP header removed.</returns>
		public String ProcessRequestToIDMSOverTLSMutual(
					String iDMSEndpoint,
					String tLSClientCertName,
					String payload,
					String sigPrivKeyName,
					String encCertName,
					String to,
					String action,
					String replyTo,
					String faultTo) {

			if (iDMSEndpoint == null)
				throw new ArgumentException("ProcessRequestToIDMSOverTLSMutual: iDMSEndpoint cannot be null");
			if (iDMSEndpoint == null)
				throw new ArgumentException("ProcessRequestToIDMSOverTLSMutual: tLSClientCertName cannot be null");
			if (payload == null)
				throw new ArgumentException("ProcessRequestToIDMSOverTLSMutual: payload cannot be null");
			if (sigPrivKeyName == null)
				throw new ArgumentException("ProcessRequestToIDMSOverTLSMutual: sigPrivKeyName cannot be null");
			if (encCertName == null)
				throw new ArgumentException("ProcessRequestToIDMSOverTLSMutual: encCertName cannot be null");
			if (to == null)
				throw new ArgumentException("ProcessRequestToIDMSOverTLSMutual: to cannot be null");
			if (action == null)
				throw new ArgumentException("ProcessRequestToIDMSOverTLSMutual: action cannot be null");
			if (replyTo == null)
				throw new ArgumentException("ProcessRequestToIDMSOverTLSMutual: replyTo cannot be null");
			if (faultTo == null)
				throw new ArgumentException("ProcessRequestToIDMSOverTLSMutual: faultTo cannot be null");

			String securedGenericIDMSRequest = SecureRequestToIDMS(payload, to, action, replyTo, faultTo, sigPrivKeyName, encCertName);
			String securedGenericIDMSResponse = SendRequestToIDMSOverTLSMutual(iDMSEndpoint, tLSClientCertName, securedGenericIDMSRequest);
			if (!CheckTSValidity(securedGenericIDMSResponse)) throw new CryptographicException("Current DateTime not beween the Timesatmp Created and Expires Date Times.\nIncoming request was:\n" + payload);
			String genericIDMSResponse = DecryptXml(securedGenericIDMSResponse);
			if (!VerifyXml(genericIDMSResponse)) throw new CryptographicException("Response message signature does not validate. Response was:\n " + genericIDMSResponse);
			String genericIDMSResponsePayload = removeSOAPHeader(genericIDMSResponse);

			return genericIDMSResponsePayload;

		}


		/// <summary>
		/// This method fully processes generic incoming IDMS requests. 
		/// The method:
		/// 	- Verifies that the current date and time of the incoming request is between the incoming message Timestamp Creates and Expires date times,
		/// 	- Decrypts the Body of the incoming message,
		/// 	- Verifies that the Signature of the message is valid and
		/// 	- If signature verification is OK removes the SOAP Header element.
		/// This method will throw a CryptographicException if the current date and time of the incoming request is not between the 
		/// incoming message Timestamp Creates and Expires date times, or if the Signature of the message is not valid.
		/// </summary>
		/// <param name="payload">The signed then encrypted incoming request.</param>
		/// <returns>A String[2] array, first String being the decrypted request, with Signature and Timestamp verified and with the SOAP header removed,
		/// and second String being the incoming IDMS request WS-Addressing MessageID that we'll have to use to respond to IDMS.</returns>
		public String ProcessIncomingIDMSRequest(String payload) {

			if (payload == null)
				throw new ArgumentException("ProcessIncomingIDMSRequest: payload cannot be null");

			if (!CheckTSValidity(payload)) throw new CryptographicException("Current DateTime not beween the incoming IDMS request Timesatmp Created and Expires Date Times.\nIncoming request was:\n" + payload);
			String decryptedPayload = DecryptXml(payload);
			if (!VerifyXml(decryptedPayload)) throw new CryptographicException("Incoming IDMS request signature does not validate. Incoming request was:\n " + decryptedPayload);
			String decryptedBody = removeSOAPHeader(decryptedPayload);

			return decryptedBody;

		}


		/// <summary>
		/// This method retrieves the WS-Addressing MessageID header text value, that we must use as the value of the RelatesTo WS-Addressing header when responding to the IDMS request.
		/// </summary>
		/// <param name="payload">The incoming IDMS request SOAP message.</param>
		/// <returns>The WS-Addressing MessageID header text value retrieved from the incoming IDMS request.</returns>
		public String GetMessageIDFromIncomingIDMSRequest(String payload) {

			if (payload == null)
				throw new ArgumentException("GetMessageIDFromIncomingIDMSRequest: payload cannot be null");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("wsa", "http://www.w3.org/2005/08/addressing");
			XmlElement messageIDNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsa:MessageID", ns) as XmlElement;
			String incomingMsgID = messageIDNode.InnerText;

			return incomingMsgID;

		}


		/// <summary>
		/// This method retrieves the WS-Addressing ReplyTo header text value, that we must use as the value of the To WS-Addressing header when responding to the IDMS request.
		/// </summary>
		/// <param name="payload">The incoming IDMS request SOAP message.</param>
		/// <returns>The WS-Addressing ReplyTo header text value retrieved from the incoming IDMS request.</returns>
		public String GetReplyToFromIncomingIDMSRequest(String payload) {

			if (payload == null)
				throw new ArgumentException("GetReplyToFromIncomingIDMSRequest: payload cannot be null");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("wsa", "http://www.w3.org/2005/08/addressing");
			XmlElement replyToNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsa:ReplyTo", ns) as XmlElement;
			String replyTo = replyToNode.InnerText;

			return replyTo;

		}


		/// <summary>
		/// This method signs and encrypts the unsecured SOAP response to an IDMS request, given certificates names, element to encrypt and required WS-Addressing information.
		/// </summary>
		/// <param name="payload">The unsecured SOAP response.</param>
		/// <param name="to">The value of the 'To' WS-Addressing header.</param>
		/// <param name="action">The value of the 'Action' WS-Addressing header.</param>
		/// <param name="relatesTo">The value of the 'RelatesTo' WS-Addressing header.</param>
		/// <param name="sigPrivKeyName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <returns>The secured (timestamped, signed and encrypted) SOAP response that can then be sent as is to the IDMS SOAP client.</returns>
		public String SecureOutgoingResponseToIDMS(
					String payload, 
					String to, 
					String action, 
					String relatesTo, 
					String sigPrivKeyName, 
					String encCertName) {

			if (payload == null)
				throw new ArgumentException("SecureOutgoingResponseToIDMS: payload cannot be null");
			if (to == null)
				throw new ArgumentException("SecureOutgoingResponseToIDMS: to cannot be null");
			if (action == null)
				throw new ArgumentException("SecureOutgoingResponseToIDMS: action cannot be null");
			if (relatesTo == null)
				throw new ArgumentException("SecureOutgoingResponseToIDMS: relatesTo cannot be null");
			if (sigPrivKeyName == null)
				throw new ArgumentException("SecureOutgoingResponseToIDMS: sigPrivKeyName cannot be null");
			if (encCertName == null)
				throw new ArgumentException("SecureOutgoingResponseToIDMS: encCertName cannot be null");

			payload = SetSOAPBodyIDAttribute(payload);
			String payloadWithAddressing = AddAdressingHeaders4Resps(payload, to, action, relatesTo);
			String payloadWithTS = AddTSSecHeaderWithDefaultValidity(payloadWithAddressing);
			String signedPayload = SignXmlResps(payloadWithTS, sigPrivKeyName);
			String encryptedBody = EncryptBodyContent(signedPayload, encCertName);

			return encryptedBody;

		}


		/// <summary>
		/// This method signs and encrypts the provided createApplication request, given certificates names and required WS-Addressing informations.
		/// The encrypted element will be {http://com/oberthur/idms/services/soap/enrolment/definitions}createApplicationIn (first child of the SOAP Body).
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn SOAP message.</param>
		/// <param name="to">The value of the 'To' WS-Addressing header.</param>
		/// <param name="action">The value of the 'Action' WS-Addressing header.</param>
		/// <param name="replyTo">The value of the 'ReplyTo/Address' WS-Addressing header.</param>
		/// <param name="faultTo">The value of the 'FaultTo/Address' WS-Addressing header.</param>
		/// <param name="sigPrivKeyName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="encCertName">A discriminant part of the DN of the recipient's certificate that must be used to encrypt the message.</param>
		/// <returns>The secured (timestamped, signed and encrypted) generic IDMS SOAP request that can then be sent as is to the IDMS server.</returns>
		public String SecureRequestToIDMS(
					String payload, 
					String to, 
					String action, 
					String replyTo, 
					String faultTo, 
					String sigPrivKeyName, 
					String encCertName) {

			if (payload == null)
				throw new ArgumentException("SecureRequestToIDMS: payload cannot be null");
			if (to == null)
				throw new ArgumentException("SecureRequestToIDMS: to cannot be null");
			if (action == null)
				throw new ArgumentException("SecureRequestToIDMS: action cannot be null");
			if (replyTo == null)
				throw new ArgumentException("SecureRequestToIDMS: replyTo cannot be null");
			if (faultTo == null)
				throw new ArgumentException("SecureRequestToIDMS: faultTo cannot be null");
			if (sigPrivKeyName == null)
				throw new ArgumentException("SecureRequestToIDMS: sigPrivKeyName cannot be null");
			if (encCertName == null)
				throw new ArgumentException("SecureRequestToIDMS: encCertName cannot be null");

			payload = SetSOAPBodyIDAttribute(payload);
			payload = AddAdressingHeaders4Reqs(payload, to, action, replyTo, faultTo);
			payload = AddTSSecHeaderWithDefaultValidity(payload);
			payload = SignXmlReqs(payload, sigPrivKeyName);

			return EncryptBodyContent(payload, encCertName);

		}


		/// <summary>
		/// Utility method sending the secure IDMS request to the IDMS server
		/// </summary>
		/// <param name="securedRequest">The String containing the SOAP request to IDMS</param>
		/// <param name="iDMSEndpoint">The endpoint of the IDMS operation to access"http://78.155.143.145:10080/enrolmentApp_WSS/service"</param>
		/// <returns>A String containing theIDMS server response</returns>
		public String SendRequestToIDMS(
					String iDMSEndpoint, 
					String securedRequest) {

			if (iDMSEndpoint == null)
				throw new ArgumentException("SendRequestToIDMS: iDMSEndpoint cannot be null");
			if (securedRequest == null)
				throw new ArgumentException("SendRequestToIDMS: securedRequest cannot be null");

			HttpWebRequest httpRequest = (HttpWebRequest) WebRequest.Create(new Uri(iDMSEndpoint));
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
		/// <param name="tLSClientCertName">A discriminant part of the DN of the certificate associated to the private key to be used to establish 
		/// the mutually authenticated TLS tunnel. (e.g. 'CN=WebPortalClientCert' or 'WebPortalClientCert').</param>
		/// <param name="securedRequest">The String containing the SOAP request to IDMS</param>
		/// <returns>A String containing the raw IDMS server response</returns>
		public String SendRequestToIDMSOverTLSMutual(
					String iDMSEndpoint, 
					String tLSClientCertName, 
					String securedRequest) {

			if (iDMSEndpoint == null)
				throw new ArgumentException("SendRequestToIDMSOverTLSMutual: iDMSEndpoint cannot be null");
			if (tLSClientCertName == null)
				throw new ArgumentException("SendRequestToIDMSOverTLSMutual: tLSClientCertName cannot be null");
			if (securedRequest == null)
				throw new ArgumentException("SendRequestToIDMSOverTLSMutual: securedRequest cannot be null");

			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
			HttpWebRequest httpRequest = (HttpWebRequest) WebRequest.Create(new Uri(iDMSEndpoint));
			X509Certificate2 certificate = GetPrivKey(tLSClientCertName);
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
		/// Utility method setting the SOAP Body element Id attribute value to '_1'.
		/// This Id attribute will be used to reference the Body when signing it.
		/// </summary>
		/// <param name="payload">The SOAP message to be modified.</param>
		/// <returns>The same SOAP message with a S:Body element having its wsu:Id attribute set to '_1'</returns>
		public String SetSOAPBodyIDAttribute(String payload) {

			if (payload == null)
				throw new ArgumentException("SetSOAPBodyIDAttribute: payload cannot be null");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			XmlElement envelopeNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope", ns) as XmlElement;
			XmlElement bodyNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body", ns) as XmlElement;
			if (bodyNode.HasAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"))
				bodyNode.RemoveAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			bodyNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_1");

			return xmlDoc.InnerXml;

		}


		/// <summary>
		/// Utility method adding the required (as per the WS-Policy fragment in the IDMSEnrolmentFacade WSDL) WS-Addressing headers 
		/// (MessageID, To, Action, ReplyTo and FaultTo) to the SOAP Header of a createApplication or getApplicationState unsecured SOAP request.
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn or getApplicationStateIn unsecured SOAP request.</param>
		/// <param name="to">The value of the To Ws-Addressing header.</param>
		/// <param name="action">The value of the Action Ws-Addressing header.</param>
		/// <param name="replyTo">The value of the ReplyTo/Address Ws-Addressing header.</param>
		/// <param name="faultTo">The value of the FaultTo/Address Ws-Addressing header.</param>
		/// <returns>The createApplication or getApplicationState SOAP request containing required WS-Addressing headers in the SOAP Header.</returns>
		public String AddAdressingHeaders4Reqs(
				String payload, 
				String to, 
				String action, 
				String replyTo, 
				String faultTo) {

			if (payload == null)
				throw new ArgumentException("AddAdressingHeaders4Reqs: payload cannot be null");
			if (to == null)
				throw new ArgumentException("AddAdressingHeaders4Reqs: to cannot be null");
			if (action == null)
				throw new ArgumentException("AddAdressingHeaders4Reqs: action cannot be null");
			if (replyTo == null)
				throw new ArgumentException("AddAdressingHeaders4Reqs: replyTo cannot be null");
			if (faultTo == null)
				throw new ArgumentException("AddAdressingHeaders4Reqs: faultTo cannot be null");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			XmlElement envelopeNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope", ns) as XmlElement;
			XmlElement headerNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header", ns) as XmlElement;
			if (headerNode == null) {
				headerNode = xmlDoc.CreateElement("s", "Header", "http://www.w3.org/2003/05/soap-envelope");
				XmlElement bodyNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body", ns) as XmlElement;
				envelopeNode.InsertBefore(headerNode, bodyNode);
			}

			XmlElement toNode = xmlDoc.CreateElement("wsa", "To", "http://www.w3.org/2005/08/addressing");
			toNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_2");
			toNode.InnerText = to;
			headerNode.AppendChild(toNode);

			XmlElement actionNode = xmlDoc.CreateElement("wsa", "Action", "http://www.w3.org/2005/08/addressing");
			actionNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_3");
			actionNode.SetAttribute("mustUnderstand", "http://www.w3.org/2003/05/soap-envelope", "true");
			actionNode.InnerText = action;
			headerNode.AppendChild(actionNode);

			XmlElement replyToNode = xmlDoc.CreateElement("wsa", "ReplyTo", "http://www.w3.org/2005/08/addressing");
			replyToNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_4");
			XmlElement replyToAddressNode = xmlDoc.CreateElement("wsa", "Address", "http://www.w3.org/2005/08/addressing");
			replyToAddressNode.InnerText = replyTo;
			replyToNode.AppendChild(replyToAddressNode);
			headerNode.AppendChild(replyToNode);

			XmlElement faultToNode = xmlDoc.CreateElement("wsa", "FaultTo", "http://www.w3.org/2005/08/addressing");
			faultToNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_5");
			XmlElement faultToAddressNode = xmlDoc.CreateElement("wsa", "Address", "http://www.w3.org/2005/08/addressing");
			faultToAddressNode.InnerText = faultTo;
			faultToNode.AppendChild(faultToAddressNode);
			headerNode.AppendChild(faultToNode);

			XmlElement messageIDNode = xmlDoc.CreateElement("wsa", "MessageID", "http://www.w3.org/2005/08/addressing");
			messageIDNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_6");
			messageIDNode.InnerText = "uuid:" + Guid.NewGuid().ToString();
			headerNode.AppendChild(messageIDNode);

			return xmlDoc.InnerXml;

		}


		/// <summary>
		/// Utility method adding the required (as per the WS-Policy fragment in the WebPortal2IDMSFacade WSDL) WS-Addressing headers 
		/// (MessageID, To, Action and RelatesTo) to the SOAP Header of a sendMasterDataOut unsecured SOAP response.
		/// </summary>
		/// <param name="payload">The unsecured sendMasterDataOut unsecured SOAP response.</param>
		/// <param name="to">The value of the To Ws-Addressing header.</param>
		/// <param name="action">The value of the Action Ws-Addressing header.</param>
		/// <param name="relatesTo">The value of the RelatesTo Ws-Addressing header (containing the value of the corresponding incoming request MessageID).</param>
		/// <returns>The createApplication or getApplicationState SOAP request containing required WS-Addressing headers in the SOAP Header.</returns>
		public String AddAdressingHeaders4Resps(
				String payload,
				String to,
				String action,
				String relatesTo) {

			if (payload == null)
				throw new ArgumentException("AddAdressingHeaders4Resps: payload cannot be null");
			if (to == null)
				throw new ArgumentException("AddAdressingHeaders4Resps: to cannot be null");
			if (action == null)
				throw new ArgumentException("AddAdressingHeaders4Resps: action cannot be null");
			if (relatesTo == null)
				throw new ArgumentException("AddAdressingHeaders4Resps: relatesTo cannot be null");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");

			XmlElement envelopeNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope", ns) as XmlElement;
			XmlElement headerNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header", ns) as XmlElement;
			if (headerNode == null) {
				headerNode = xmlDoc.CreateElement("s", "Header", "http://www.w3.org/2003/05/soap-envelope");
				XmlElement bodyNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body", ns) as XmlElement;
				envelopeNode.InsertBefore(headerNode, bodyNode);
			}

			XmlElement toNode = xmlDoc.CreateElement("wsa", "To", "http://www.w3.org/2005/08/addressing");
			toNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_2");
			toNode.InnerText = to;
			headerNode.AppendChild(toNode);

			XmlElement actionNode = xmlDoc.CreateElement("wsa", "Action", "http://www.w3.org/2005/08/addressing");
			actionNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_3");
			actionNode.SetAttribute("mustUnderstand", "http://www.w3.org/2003/05/soap-envelope", "true");
			actionNode.InnerText = action;
			headerNode.AppendChild(actionNode);

			XmlElement relatesToNode = xmlDoc.CreateElement("wsa", "RelatesTo", "http://www.w3.org/2005/08/addressing");
			relatesToNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_4");
			relatesToNode.InnerText = relatesTo;
			headerNode.AppendChild(relatesToNode);

			XmlElement messageIDNode = xmlDoc.CreateElement("wsa", "MessageID", "http://www.w3.org/2005/08/addressing");
			messageIDNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_5");
			messageIDNode.InnerText = "uuid:" + Guid.NewGuid().ToString();
			headerNode.AppendChild(messageIDNode);

			return xmlDoc.InnerXml;

		}


		/// <summary>
		/// Utility method adding the required wsu:Timestamp element (as per the WS-Policy fragment in the IDMSEnrolmentFacade WSDL) 
		/// to the wsse:Security Header of a SOAP message to be sent to IDMS.
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn or getApplicationState unsecured SOAP request.</param>
		/// <returns>The createApplication or getApplicationState SOAP request containing required Timestamp in the WS-Security /S:Envelope/S:Header/wsse:Security header.</returns>
		public String AddTSSecHeaderWithDefaultValidity(String payload) {

			if (payload == null)
				throw new ArgumentException("AddTSSecHeaderWithDefaultValidity: payload cannot be null");

			return AddTSSecHeader(payload, "5");

		}


		/// <summary>
		/// Utility method adding the required wsu:Timestamp element (as per the WS-Policy fragment in the IDMSEnrolmentFacade WSDL) 
		/// to the wsse:Security Header of a createApplication or getApplicationState unsecured SOAP request.
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn or getApplicationState unsecured SOAP request.</param>
		/// <param name="validity">A String containing the validity period of the Timestamp to be created.</param>
		/// <returns>The createApplication or getApplicationState SOAP request containing required Timestamp in the WS-Security /S:Envelope/S:Header/wsse:Security header.</returns>
		public String AddTSSecHeader(
					String payload, 
					String validity) {

			if (payload == null)
				throw new ArgumentException("AddTSSecHeader: payload cannot be null");
			if (payload == null)
				throw new ArgumentException("AddTSSecHeader: validity cannot be null");

			int validityInt = 0;
			try {
				validityInt = Int16.Parse(validity);
			} catch {
				throw new CryptographicException("Timestamp validity is not a valid short");
			}

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
			createdNode.InnerText = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
			timestampNode.AppendChild(createdNode);

			XmlElement expiresNode = xmlDoc.CreateElement("wsu", "Expires", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			expiresNode.InnerText = DateTime.Now.AddMinutes(validityInt).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
			timestampNode.AppendChild(expiresNode);

			securityNode.AppendChild(timestampNode);

			return xmlDoc.InnerXml;

		}


		/// <summary>
		/// Utility method verifying that current Date is between the Created and Expires dates of the wsu:Timestamp element of the received SOAP message.
		/// </summary>
		/// <param name="payload">The received SOAP message.</param>
		/// <returns>A Boolean, true if current Date is between the Created and Expires dates of the wsu:Timestamp element of the received SOAP message, false if not.</returns>
		public Boolean CheckTSValidity(String payload) {

			if (payload == null)
				throw new ArgumentException("CheckTSValidity: payload cannot be null");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			ns.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
			XmlElement createdNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/wsu:Timestamp/wsu:Created", ns) as XmlElement;
			XmlElement expiresNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/wsu:Timestamp/wsu:Expires", ns) as XmlElement;
			DateTime created = DateTime.Parse(createdNode.InnerText).ToUniversalTime();
			DateTime expires = DateTime.Parse(expiresNode.InnerText).ToUniversalTime();

			return (DateTime.Now.ToUniversalTime().CompareTo(created) > 0 && DateTime.Now.ToUniversalTime().CompareTo(expires) < 0);

		}


		/// <summary>
		/// Removes SOAP Header so that it will be easier for the ASP scripts to work with the message
		/// </summary>
		/// <param name="payload">The SOAP message from which we want to remove the Header.</param>
		/// <returns>The SOAP message without Header</returns>
		public String removeSOAPHeader(String payload) {

			if (payload == null)
				throw new ArgumentException("removeSOAPHeader: payload cannot be null");

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
		/// Utility method signing the createApplicationIn or getApplicationState unsecured SOAP request as per the WS-Policy fragment in the IDMSEnrolmentFacade WSDL.
		/// The Timestamp, the WS-Addressing headers and the Body of the message must be signed.
		/// </summary>
		/// <param name="payload">The unsecured createApplicationIn or getApplicationState unsecured SOAP request.</param>
		/// <param name="sigPrivKeyName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <returns>The createApplicationIn or getApplicationState SOAP request signed as expected by the IDMS server.</returns>
		public String SignXmlReqs(
					String payload, 
					String sigPrivKeyName) {

			if (payload == null)
				throw new ArgumentException("SignXmlReqs: payload cannot be null");
			if (sigPrivKeyName == null)
				throw new ArgumentException("SignXmlReqs: sigPrivKeyName canot be null");

			String[] references = new String[7];
			references[0] = "#_1";
			references[1] = "#_2";
			references[2] = "#_3";
			references[3] = "#_4";
			references[4] = "#_5";
			references[5] = "#_6";
			references[6] = "#_7";

			return SignXml(payload, sigPrivKeyName, references);

		}


		/// <summary>
		/// Utility method signing the sendMasterDataOut SOAP response as per the WS-Policy fragment in the WebPortal2IDMSFacade WSDL.
		/// The Timestamp, the WS-Addressing headers and the Body of the message must be signed.
		/// </summary>
		/// <param name="payload">The unsecured sendMasterDataOut SOAP response.</param>
		/// <param name="sigPrivKeyName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <returns>The sendMasterDataOut SOAP response signed as expected by the IDMS server.</returns>
		public String SignXmlResps(
					String payload, 
					String sigPrivKeyName) {

			if (payload == null)
				throw new ArgumentException("SignXmlResps: payload cannot be null");
			if (sigPrivKeyName == null)
				throw new ArgumentException("SignXmlResps: sigPrivKeyName canot be null");

			String[] references = new String[6];
			references[0] = "#_1";
			references[1] = "#_2";
			references[2] = "#_3";
			references[3] = "#_4";
			references[4] = "#_5";
			references[5] = "#_7";

			return SignXml(payload, sigPrivKeyName, references);

		}


		/// <summary>
		/// Utility method signing the all the elements with URIs specified in the references List parameter.
		/// Resulting SOAP message follows the WS-Policy fragment in the IDMS WSDLs, having the KeyInfo 
		/// block of the Signature block pointing to an external BinarySecurityToken of type 
		/// "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" in the wsse:Security header 
		/// via a SecurityTokenReference/Reference element.
		/// 
		/// In the end, we have a Security header such as:
		/// 
		/// <![CDATA[
		/// <code>
		///		<wsse:Security
		///				xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
		///			<wsu:Timestamp wsu:Id="_7"...</wsu:Timestamp>
		///			<wsse:BinarySecurityToken
		///					EncodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
		///					ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
		///					u:Id="_BinarySecurityToken1">
		///				MIIDDzCC...vTsEVUQ==
		///			</wsse:BinarySecurityToken>
		///			<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
		///				<SignedInfo>...</ SignedInfo>
		///				<SignatureValue >...</SignatureValue>
		///				<KeyInfo>
		///					<wsse:SecurityTokenReference>
		///						<wsse:Reference URI = "#_BinarySecurityToken1" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" />
		///					</wsse:SecurityTokenReference>
		///				</KeyInfo>
		///			</Signature>
		///		</wsse:Security>
		/// </code>
		/// ]]>
		/// </summary>
		/// <param name="payload">The SOAP message to be signed.</param>
		/// <param name="sigPrivKeyName">A discriminant part of the DN of the certificate associated to the private key that must be used to sign the message.</param>
		/// <param name="references">A String[] containing te URIs of the elements to be signed.</param>
		/// <returns>The SOAP message, signed as expected by the IDMS server.</returns>
		public String SignXml(
					String payload, 
					String sigPrivKeyName, 
					String[] references) {

			if (payload == null)
				throw new ArgumentException("SignXml: payload cannot be null");
			if (sigPrivKeyName == null)
				throw new ArgumentException("SignXml: sigPrivKeyName canot be null");
			if (references == null)
				throw new ArgumentException("SignXml: references canot be null");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);
			XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
			ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
			ns.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			XmlElement headerNode = xmlDoc.DocumentElement.SelectSingleNode("//s:Header", ns) as XmlElement;
			XmlElement securityNode = xmlDoc.DocumentElement.SelectSingleNode("//wsse:Security", ns) as XmlElement;
			if (securityNode == null) securityNode = xmlDoc.CreateElement("wsse", "Security", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");

			X509Certificate2 signingCert = GetPrivKey(sigPrivKeyName);
			XmlElement binarySecurityTokenNode = xmlDoc.CreateElement("wse", "BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
			binarySecurityTokenNode.SetAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
			binarySecurityTokenNode.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
			binarySecurityTokenNode.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "_BinarySecurityToken1");
			binarySecurityTokenNode.InnerText = Convert.ToBase64String(signingCert.GetRawCertData());
			securityNode.AppendChild(binarySecurityTokenNode);
			headerNode.AppendChild(securityNode);

			RSACryptoServiceProvider key = (RSACryptoServiceProvider)signingCert.PrivateKey;
			SignedXmlWithId signedXml = new SignedXmlWithId(xmlDoc);
			signedXml.SigningKey = key;

			signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			KeyInfo keyInfo = new KeyInfo();
			keyInfo.AddClause(new SecurityTokenReference("_BinarySecurityToken1"));
			signedXml.KeyInfo = keyInfo;

			XmlDsigExcC14NTransform transform = new XmlDsigExcC14NTransform();

			foreach(String s in references) {
				Reference reference = new Reference(s);
				reference.DigestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
				reference.AddTransform(transform);
				signedXml.AddReference(reference);
			}

			signedXml.ComputeSignature();
			XmlElement signedElement = signedXml.GetXml();
			securityNode.AppendChild(signedElement);

			return xmlDoc.InnerXml;

		}

		/// <summary>
		/// Utility method encrypting the content ('http://www.w3.org/2001/04/xmlenc#Content') of the SOAP message Body to be sent to IDMS.
		/// 
		/// The way .Net handles encryption does not comply with IDMS SecurityPolicy.
		/// We then need to reformat the message after encryption so that IDMS can decrypt it.
		/// 
		///  Basically, the EncryptedKey block generated by.Net is in /S:Envelope/S:Body/e:EncryptedData/ds:KeyInfo under this format : 
		///  <code>
		///  <![CDATA[
		///   	<xenc:EncryptedData>
		///   		<xenc:CipherData>
		///   			<xenc:CipherValue>...</xenc:CipherValue>
		///   		</xenc:CipherData>
		/// 		<ds:KeyInfo>
		///  			<xenc:EncryptedKey
		///					xmlns:ns17= "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512"
		///					xmlns:ns16= "http://schemas.xmlsoap.org/soap/envelope/">
		///					<xenc:EncryptionMethod Algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
		///					<ds:KeyInfo>
		///  					<ds:X509Data>
		///  						<ds:X509IssuerSerial>
		///  							<ds:X509IssuerName>CN=SUNCA, OU=JWS, O=SUN, ST=Some-State, C=AU</ds:X509IssuerName>
		///  							<ds:X509SerialNumber>2</ds:X509SerialNumber>
		///  						</ds:X509IssuerSerial>
		///  					</ds:X509Data>
		///  				</ds:KeyInfo>
		///  				<xenc:CipherData>
		///  					<xenc:CipherValue>c6DN7B.....O/BATrcM=</xenc:CipherValue>
		///  				</xenc:CipherData>
		///  			</xenc:EncryptedKey>
		///  		</ds:KeyInfo>
		///   	</xenc:EncryptedData>
		///  ]]>
		///  </code>
		///  	
		///  IDMS expects the EncryptedKey block to be outside of the EncryptedData block, in the /S:Envelope/S:Header/wsse:/Security block, 
		///  and to reference the EncryptedData it encrypted using a /ReferenceList/DataReference construct, in the following format :
		///  	
		/// <code>
		/// <![CDATA[
		///  	<xenc:EncryptedKey>
		///       <xenc:EncryptionMethod Algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
		///       <ds:KeyInfo xmlns:xsi= "http://www.w3.org/2001/XMLSchema-instance" xsi:type= "KeyInfoType">
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
		///   	...
		///   	<xenc:EncryptedData Id = "_payload">
		///   		<xenc:CipherData>
		///   			<xenc:CipherValue>...</xenc:CipherValue>
		///   		</xenc:CipherData>
		///   	</xenc:EncryptedData>
		///  ]]>
		///  </code>
		/// </summary>
		/// <param name="payload">The unencrypted SOAP message to encrypt.</param>
		/// <param name="encCertName">A discriminant part of the DN of the certificate that must be used to encrypt the SOAP message.</param>
		/// <returns>The SOAP message, with the Body content encrypted.</returns>
		public String EncryptBodyContent(
				String payload,
				String encCertName) {

			if (payload == null)
				throw new ArgumentNullException("EncryptBodyContent: payload cannot be null");
			if (encCertName == null)
				throw new ArgumentNullException("EncryptBodyContent: encCertName cannot be null");

			XmlDocument xmlDoc = new XmlDocument();
			xmlDoc.PreserveWhitespace = true;
			xmlDoc.LoadXml(payload);

			try {
				// Create a symmetric AES session key 
				RijndaelManaged sessionKey = new RijndaelManaged();
				sessionKey.KeySize = 128;

				// Now create the EncryptedKey block, that will contain the symmetric session key encrypted with the recipient's public key retrieved from its certificate
				EncryptedKey ek = new EncryptedKey();
				ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
				//ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl);

				// Retrieve the RSA asymmetric encryption key from the recipient's certificate
				X509Certificate2 EncryptionCertificate = GetCert(encCertName);
				RSACryptoServiceProvider RSA = (RSACryptoServiceProvider)EncryptionCertificate.PublicKey.Key;
				// Encrypt the symmetric session key with this asymmetric key
				byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, RSA, false);
				ek.CipherData = new CipherData(encryptedKey);

				// Add a KeyInfo block to the EncryptedKey referencing the recipient's public key
				KeyInfoX509Data kix509 = new KeyInfoX509Data();
				kix509.AddIssuerSerial(EncryptionCertificate.Issuer, EncryptionCertificate.SerialNumber);
				ek.KeyInfo.AddClause(kix509);

				// Create a DataReference to the EncryptedData that will be encrypted by the symmetric session key
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

				XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
				ns.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");
				XmlElement bodyNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Body", ns) as XmlElement;

				EncryptedXml eXml = new EncryptedXml();
				byte[] encryptedElement = eXml.EncryptData(bodyNode, sessionKey, true);
				edElement.CipherData.CipherValue = encryptedElement;
				EncryptedXml.ReplaceElement(bodyNode, edElement, true);

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
		/// Utility method verifying the signature of a SOAP message received from IDMS, retrieving the certificate's 
		/// public key that must be used to verify the signature of the message dynamically.
		/// This method will throw a CryptographicException if the certificate used to verify the message 
		/// is directly embedded in the message and cannot be found in the LocalMachine/TrustedPeople store.
		/// </summary>
		/// <param name="payload">The signed SOAP message received from IDMS.</param>
		/// <returns>A Boolean, true if signature verifies, false if not.</returns>
		public Boolean VerifyXml(String payload) {

			if (payload == null)
				throw new ArgumentException("VerifyXml: payload cannot be null");

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

			XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
			// Throw an exception if no signature was found.
			if (nodeList.Count <= 0) 
				throw new CryptographicException("Verification failed: No Signature was found in the document.");

			// According to IDMS SecurityPolicy there should be only one signature for the entire XML document.  
			// We throw an exception if more than one signature was found.
			if (nodeList.Count >= 2) 
				throw new CryptographicException("Verification failed: More that one signature was found for the document.");

			XmlElement signatureNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/ds:Signature", ns) as XmlElement;
			SignedXmlWithId signedXml = new SignedXmlWithId(xmlDoc);
			signedXml.LoadXml(signatureNode);

			X509Certificate2 signingCert = null;
			XmlElement x509IssuerNameNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/ds:X509Data/ds:X509IssuerSerial/ds:X509IssuerName", ns) as XmlElement;
			XmlElement x509SerialNumberNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/ds:X509Data/ds:X509IssuerSerial/ds:X509SerialNumber", ns) as XmlElement;
			XmlElement referenceNode = xmlDoc.DocumentElement.SelectSingleNode("/s:Envelope/s:Header/wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference", ns) as XmlElement;

			if (x509SerialNumberNode != null) {
				signingCert = GetCertByIssuerSerial(x509IssuerNameNode.InnerText, x509SerialNumberNode.InnerText);

			} else if (referenceNode != null) {
				String refId = referenceNode.GetAttribute("URI");
				refId = refId.Substring(1);
				ns.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
				XmlNodeList bstNodes = xmlDoc.SelectNodes("//*[@wsu:Id=\"" + refId + "\"]", ns);
				if(bstNodes.Count == 0) 
					throw new CryptographicException("Unable to find the Certificate referenced by SecurityTokenReference/Reference URI. Incoming message to validate was :\n " + payload);
				if (bstNodes.Count > 1)
					throw new CryptographicException("There are more than 1 Certificate referenced by SecurityTokenReference/Reference URI. Incoming message to validate was :\n " + payload);
				XmlElement bstNode = xmlDoc.SelectSingleNode("//*[@wsu:Id=\"" + refId + "\"]", ns) as XmlElement;
				signingCert = new X509Certificate2(Convert.FromBase64String(bstNode.InnerText));
				// Will throw a CryptographicException if cert not found
				try {
					X509Certificate2 certFromStore = GetCertByIssuerSerial(signingCert.Issuer, signingCert.SerialNumber);
				} catch {
					CryptographicException ce = new CryptographicException("Certificate used to sign message was not trusted. Incoming message to validate was :\n " + payload);
					throw ce;
				}
			}

			return signedXml.CheckSignature((RSACryptoServiceProvider) signingCert.PublicKey.Key);

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
		///   	<xenc:EncryptedKey>
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
		///   	...
		///   	<xenc:EncryptedData Id = "_5008">
		///   		<xenc:CipherData>
		///   			<xenc:CipherValue>...</xenc:CipherValue>
		///   		</xenc:CipherData>
		///   	</xenc:EncryptedData>
		///  ]]>
		///  </code>
		///   	
		/// As .Net doesn't support the EncryptedKey/ReferenceList/DataReference method to reference EncryptedData blocks to be decrypted 
		/// from the symmetric EncryptedKey blocks that encrypted them we must reformat the message to put the EncryptedKey 
		/// where .Net will be able to retrieve it, embedded in the /S:Envelope/S:Body/e:EncryptdData/ds:KeyInfo block, 
		/// and under this format : 
		///   	
		///  <code>
		///  <![CDATA[
		///   	<xenc:EncryptedData>
		///   		<xenc:CipherData>
		///   			<xenc:CipherValue>...</xenc:CipherValue>
		///   		</xenc:CipherData>
		///   		<ds:KeyInfo>
		///   			<xenc:EncryptedKey
		///					  xmlns:ns17= "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512"
		///					  xmlns:ns16= "http://schemas.xmlsoap.org/soap/envelope/">
		///				   <xenc:EncryptionMethod Algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
		///				   <ds:KeyInfo>
		///   					<ds:KeyName>CN=xwssecurityclient, OU= SUN, O=Internet Widgits Pty Ltd, ST=Some-State, C=AU</ds:KeyName>
		///   				</ds:KeyInfo>
		///   				<xenc:CipherData>
		///   					<xenc:CipherValue>c6DN7B.....O/BATrcM=</xenc:CipherValue>
		///   				</xenc:CipherData>
		///   			</xenc:EncryptedKey>
		///   		</ds:KeyInfo>
		///   	</xenc:EncryptedData>
		///  ]]>
		///  </code>
		///   	
		/// Note that we don't use X509Data to reference the asymmetric EncryptedKey that was used to decrypt
		/// the symmetric EncryptedKey because of the difference in the representation of the State RDN (S in Java and 
		/// ST in Microsoft) in the Certificates DN, and the.Net stack is not able to retrieve the Certificate from the 
		/// Issuer DN provided by the Glassfish/Metro stack.
		/// We use KeyName instead. 
		/// 
		/// </summary>
		/// <param name="payload">The unencrypted SOAP message to encrypt.</param>
		/// <returns>The decrypted SOAP message.</returns>
		public string DecryptXml(String payload) {

			if (payload == null)
				throw new ArgumentNullException("DecryptXml: payload cannot be null");

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
				X509Certificate2 cert = GetPrivKeyByIssuerSerial(X509IssuerNameNode.InnerText, X509SerialNumberNode.InnerText);
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
				exml.AddKeyNameMapping(KeyNameString, (RSA) cert.PrivateKey);
				exml.DecryptDocument();
				//exml.DecryptData(encData, exml.GetDecryptionKey(encData, "http://www.w3.org/2001/04/xmlenc#aes128-cbc"));
			} catch (Exception e) {
				CryptographicException ce = new CryptographicException("An exception was raised while trying to decrypt the message.\n" + e.Message + "\n" + e.StackTrace);
				throw ce;
			}
			return xmlDoc.InnerXml;

		}


		/// <summary>
		/// Utility method returning the X509Certificate2 object in the LocalMachine/Personal Windows Certificate Store matching the provided certName.
		/// </summary>
		/// <param name="certName">A discriminant part of the DN of the certificate to be retrieved (e.g. 'CN=IDMSClient' or 'IDMSClient').</param>
		/// <returns>The X509Certificate2 object in the LocalMachine/Personal Windows Certificate Store matching the provided certName.</returns>
		private X509Certificate2 GetPrivKey(String certName) {

			return GetKeyFromStore(certName, "My");

		}


		/// <summary>
		/// Utility method returning the X509Certificate2 object in the LocalMachine Windows Certificate Store matching the provided certName.
		/// </summary>
		/// <param name="certName">A discriminant part of the DN of the certificate to be retrieved (e.g. 'CN=IDMSClient' or 'IDMSClient').</param>
		/// <returns>The X509Certificate2 object in the LocalMachine/TrustedPeople Windows Certificate Store matching the provided certName.</returns>
		private X509Certificate2 GetCert(String certName) {

			return GetKeyFromStore(certName, "TrustedPeople");

		}


		/// <summary>
		/// Utility method returning the X509Certificate2 object in the LocalMachine/storeName Windows Certificate Store matching the provided certName.
		/// </summary>
		/// <param name="certName">A discriminant part of the DN of the certificate to be retrieved (e.g. 'CN=IDMSClient' or 'IDMSClient').</param>
		/// <param name="storeName">The Windows Certificate Store Name where to look for the X509Certificate2 object.</param>
		/// <returns>The X509Certificate2 object in the LocalMachine/storeName Windows Certificate Store matching the provided certName.</returns>
		private X509Certificate2 GetKeyFromStore(String certName, String storeName) {

			X509Store my = new X509Store(storeName, StoreLocation.LocalMachine);
			my.Open(OpenFlags.ReadOnly);
			X509Certificate2 signingCert = null;
			foreach (X509Certificate2 cert in my.Certificates) {
				if (cert.Subject.Contains(certName)) {
					signingCert = cert;
					break;
				}
			}
			if (signingCert == null) {
				throw new CryptographicException("Unable to find certificate in the LocalMachine store, under " + storeName + "/Certificates");
			}
			return signingCert;

		}


		/// <summary>
		/// Utility method returning the X509Certificate2 object in the LocalMachine Windows Certificate Store issued by the provided Issuer and having the serialNumber provided.
		/// </summary>
		/// <param name="issuer">The DN of the issuing Authority</param>
		/// <param name="serial">The serial number of the certificate to be retrieved</param>
		/// <returns>The X509Certificate2 object in the LocalMachine/Personal Windows Certificate Store issued by the provided Authority and having the provided SerialNumber</returns>
		private X509Certificate2 GetPrivKeyByIssuerSerial(String issuer, String serial) {

			return GetPrivKeyByIssuerSerialFromStore(issuer, serial, "My");

		}


		/// <summary>
		/// Utility method returning the X509Certificate2 object in the LocalMachine Windows Certificate Store issued by the provided Issuer and having the serialNumber provided.
		/// </summary>
		/// <param name="issuer">The DN of the issuing Authority</param>
		/// <param name="serial">The serial number of the certificate to be retrieved</param>
		/// <returns>The X509Certificate2 object in the LocalMachine/TrustedPeople Windows Certificate Store issued by the provided Authority and having the provided SerialNumber</returns>
		private X509Certificate2 GetCertByIssuerSerial(String issuer, String serial) {

			return GetPrivKeyByIssuerSerialFromStore(issuer, serial, "TrustedPeople");

		}


		/// <summary>
		/// Utility method returning the X509Certificate2 object in the LocalMachine Windows Certificate Store issued by the provided Issuer and having the serialNumber provided.
		/// 1. There is a Windows bug : certificates with DN like 
		///		CN =SUNCA, OU=JWS, O=SUN, ST=Some-State, C=AU 
		/// are registered as 
		///		CN =SUNCA, OU=JWS, O=SUN, S=Some-State, C=AU
		/// So we need to rewrite 'S=' or 'ST=' to 'STATE=' to compare issuers... Need to do cert DN C14N here!!
		/// 2. Other problem : we can't always compare SerialNumber as String as some certs come with a SerialNumber like '02'
		/// and when imported in Windows cert store will end up having a SerialNumber of '2'.
		/// On the other hand some certs have a SerialNumber which is not RFC2459 compliant and won't cast into a Long, so for 
		/// these certs we must do String comparison (e.g. certs generated by OT PKI have SerialNumbers like '00bb8a343702486054').
		/// We use ToUpper() while doing String comparison because Base16 or Base64 representations of bigints might be different from one platform to the other.
		/// </summary>
		/// <param name="issuer">The DN of the issuing Authority</param>
		/// <param name="serial">The serial number of the certificate to be retrieved</param>
		/// <param name="storeName">The Windows Certificate Store Name where to look for the X509Certificate2 object.</param>
		/// <returns>The X509Certificate2 object in the LocalMachine/storeName Windows Certificate Store issued by the provided Authority and having the provided SerialNumber</returns>
		private X509Certificate2 GetPrivKeyByIssuerSerialFromStore(String issuer, String serial, String storeName) {

			issuer = issuer.Replace("S=", "ST=").Replace("ST=", "STATE=");
			X509Store my = new X509Store(storeName, StoreLocation.LocalMachine);
			my.Open(OpenFlags.ReadOnly);
			X509Certificate2 signingCert = null;
			try {
				long serialLong = long.Parse(serial);
				foreach (X509Certificate2 cert in my.Certificates) {
					String realIssuer = cert.Issuer.Replace("S=", "ST=").Replace("ST=", "STATE=");
					// Got to avoid exceptions here when comparing with certs in store whith serial numbers are not integers as per RFC2459
					try {
						long certSerialInt = long.Parse(cert.SerialNumber);
						if (serialLong.Equals(certSerialInt) && issuer.Equals(realIssuer)) {
							signingCert = cert;
							break;
						}
					} catch {
						// Just swallow exception silently
					}
				}
			} catch {
				foreach (X509Certificate2 cert in my.Certificates) {
					String realIssuer = cert.Issuer.Replace("S=", "ST=").Replace("ST=", "STATE=");
					if (serial.ToUpper().Equals(cert.SerialNumber.ToUpper()) && issuer.Equals(realIssuer)) {
						signingCert = cert;
						break;
					}
				}
			}
			if (signingCert == null) {
				throw new CryptographicException("Unable to find certificate in the LocalMachine store, under " + storeName + "/ Certificates");
			}

			return signingCert;

		}


	}


	/// <summary>
	/// Utility class overriding the GetIdElement method of SignedXml class to allow for finding elements by Id attribute.
	/// defined in http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd
	/// </summary>
	[ComVisible(false)]
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
				XmlNodeList idElems = doc.SelectNodes("//*[@wsu:Id=\"" + id + "\"]", nsManager);
				if(idElems.Count == 0)
					throw new CryptographicException("No element with Id " + id + " in the document. Incoming message is :\n " + doc.InnerXml);
				if (idElems.Count > 1)
					throw new CryptographicException("There are more than 1 element with Id " + id + " in the document. Incoming message is :\n " + doc.InnerXml);
				idElem = doc.SelectSingleNode("//*[@wsu:Id=\"" + id + "\"]", nsManager) as XmlElement;
			}
			return idElem;
		}

	}


	/// <summary>
	/// Utility class overriding the GetXml method of the KeyInfoClause class allowing for the building of KeyInfo/SecurityTokenReference/Reference block.
	/// </summary>
	[ComVisible(false)]
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
