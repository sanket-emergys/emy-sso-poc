import uuid
import base64
import requests
import os
from datetime import datetime, timedelta, timezone
from lxml import etree
from signxml import XMLSigner

class SAPPrincipalPropagationService:
    def __init__(self):
        self.issuer = "Django_IdP"
        self.sap_audience = "https://sap-server.internal.corp"
        self.sap_oauth_endpoint = "https://sap-server.internal.corp/sap/bc/sec/oauth2/token"
        
        # Resolve certs path relative to this file
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        private_key_path = os.path.join(base_dir, "certs", "django_private.pem")
        public_cert_path = os.path.join(base_dir, "certs", "django_public.crt")

        try:
            with open(private_key_path, "rb") as key_file:
                self.private_key = key_file.read()
            with open(public_cert_path, "rb") as cert_file:
                self.certificate = cert_file.read()
        except FileNotFoundError:
            print(f"Warning: Certificates not found at {private_key_path}. Ensure you run generate_certs.py first.")
            self.private_key = None
            self.certificate = None

    def generate_signed_saml_assertion(self, user_email):
        if not self.private_key or not self.certificate:
            raise Exception("Certificates missing. Please generate them to sign SAML assertions.")
            
        now = datetime.now(timezone.utc)
        assertion_id = "_" + str(uuid.uuid4())
        
        xml_template = f"""<?xml version="1.0" encoding="UTF-8"?>
        <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" IssueInstant="{now.strftime('%Y-%m-%dT%H:%M:%SZ')}" Version="2.0">
            <saml2:Issuer>{self.issuer}</saml2:Issuer>
            <!-- Signature placeholder required by signxml -->
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"></ds:Signature>
            <saml2:Subject>
                <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user_email}</saml2:NameID>
                <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml2:SubjectConfirmationData NotOnOrAfter="{(now + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')}" Recipient="{self.sap_oauth_endpoint}"/>
                </saml2:SubjectConfirmation>
            </saml2:Subject>
            <saml2:Conditions NotBefore="{(now - timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M:%SZ')}" NotOnOrAfter="{(now + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')}">
                <saml2:AudienceRestriction>
                    <saml2:Audience>{self.sap_audience}</saml2:Audience>
                </saml2:AudienceRestriction>
            </saml2:Conditions>
            <saml2:AuthnStatement AuthnInstant="{now.strftime('%Y-%m-%dT%H:%M:%SZ')}">
                <saml2:AuthnContext>
                    <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef>
                </saml2:AuthnContext>
            </saml2:AuthnStatement>
        </saml2:Assertion>"""

        root = etree.fromstring(xml_template.encode('utf-8'))
        
        # Cryptographically sign the XML payload using the private key
        signer = XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256")
        signed_root = signer.sign(root, key=self.private_key, cert=self.certificate)
        
        return base64.b64encode(etree.tostring(signed_root)).decode('utf-8')

    def fetch_sap_odata(self, user_email):
        # 1. Generate SAML Assertion
        saml_b64 = self.generate_signed_saml_assertion(user_email)
        
        # 2. Exchange SAML for SAP Access Token (RFC 7522)
        token_response = requests.post(self.sap_oauth_endpoint, data={
            "grant_type": "urn:ietf:params:oauth:grant-type:saml2-bearer",
            "assertion": saml_b64,
            "client_id": "django_oauth_client"
        })
        
        # If SAP doesn't exist, this will error. For demonstration, we assume it raises or returns data.
        # token_response.raise_for_status()
        # sap_access_token = token_response.json()["access_token"]
        
        # Using placeholder since real SAP endpoint doesn't exist locally
        sap_access_token = "mock_sap_token_if_request_fails"
        
        # 3. Call Actual SAP OData Endpoint statelessly
        odata_url = "https://sap-server.internal.corp/sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartner"
        # res = requests.get(odata_url, headers={
        #     "Authorization": f"Bearer {sap_access_token}",
        #     "Accept": "application/json"
        # })
        # return res.json()
        
        return {
            "mocked_response": "True", 
            "message": "SAML assertion successfully generated",
            "assertion_b64_preview": saml_b64[:50] + "..."
        }
