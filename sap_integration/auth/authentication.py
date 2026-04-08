import jwt
from jwt import PyJWKClient
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

class AzureJWTAuthentication(BaseAuthentication):
    def __init__(self):
        # Allow missing settings for local testing without crashing on start
        self.tenant_id = getattr(settings, 'AZURE_TENANT_ID', 'dummy-tenant-id')
        self.client_id = getattr(settings, 'AZURE_CLIENT_ID', 'dummy-client-id')
        
        self.jwks_url = f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"
        self.jwks_client = PyJWKClient(self.jwks_url)

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]
        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
            )
            # Create a stateless user object (or map to a Django User)
            user = type('AzureUser', (object,), {
                "is_authenticated": True, 
                "email": payload.get('preferred_username'),
                "sap_remote_id": payload.get('preferred_username') # Usually mapped
            })()
            return (user, token)
            
        except jwt.PyJWKClientError:
            raise AuthenticationFailed("Unable to fetch public keys from Azure AD.")
        except jwt.InvalidTokenError as e:
            raise AuthenticationFailed(f"Invalid token: {str(e)}")
