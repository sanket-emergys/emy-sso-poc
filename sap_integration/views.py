from rest_framework.views import APIView
from rest_framework.response import Response
from .services.sap_service import SAPPrincipalPropagationService
from .auth.authentication import AzureJWTAuthentication

class SAPDataView(APIView):
    # Enforce Azure AD JWT auth for this endpoint
    authentication_classes = [AzureJWTAuthentication]

    def get(self, request):
        sap_service = SAPPrincipalPropagationService()
        try:
            # Use the validated identity extracted from the JWT
            user_email = request.user.sap_remote_id if hasattr(request.user, 'sap_remote_id') else 'dummy@user.com'
            data = sap_service.fetch_sap_odata(user_email)
            return Response(data)
        except Exception as e:
            return Response({"error": "SAP integration failed", "details": str(e)}, status=502)
