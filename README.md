# Django SAP SAML Integration Setup

Follow these exact steps to set up and run the application locally.

## Installation & Setup

**1. Create and activate a Python virtual environment**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**2. Install all dependencies**
```powershell
pip install -r requirements.txt
```

**3. Generate SAML Certificates**
Creates the required dummy `django_private.pem` and `django_public.crt` files needed for the SAML assertions to execute without errors.
```powershell
python generate_certs.py
```

**4. Run Database Migrations**
```powershell
python manage.py migrate
```

**5. Start the Development Server**
```powershell
python manage.py runserver
```

---

## Testing Your Endpoints
Once running, you can open a new terminal to verify connectivity:

**Health Check (Public):**
```powershell
curl http://127.0.0.1:8000/
```

**SAP Integration (Secure):**
```powershell
curl http://127.0.0.1:8000/api/sap-data/
```
*(Without a valid Azure AD MSAL Token, this will securely return `401 Unauthorized`.)*
