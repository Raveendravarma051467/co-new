# # # backend/app.py
# # from flask import Flask, request, jsonify, url_for, flash, session, current_app, Blueprint
# # from flask_login import LoginManager, login_user, current_user, login_required, UserMixin, logout_user
# # from google.oauth2 import id_token
# # from google.auth.transport import requests as google_requests
# # from google.cloud import storage
# # from flask_cors import CORS
# # import os
# # import logging
# # from dotenv import load_dotenv
# # # --- NEW: Import password hashing utilities ---
# # from werkzeug.security import generate_password_hash, check_password_hash
# # import uuid # Used to generate unique IDs for new users

# # # Load environment variables from .env file FIRST
# # load_dotenv()

# # # --- Explicitly set GOOGLE_APPLICATION_CREDENTIALS from .env ---
# # credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS_PATH')
# # if credentials_path:
# #     os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials_path
# # else:
# #     logging.warning("GOOGLE_APPLICATION_CREDENTIALS_PATH not found in .env. Google Cloud Storage may not authenticate correctly.")

# # # Configure logging
# # logging.basicConfig(level=logging.INFO)
# # logger = logging.getLogger(__name__)

# # app = Flask(__name__)
# # app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default_super_secret_key_if_not_set')
# # app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
# # app.config['GCS_BUCKET_NAME'] = os.getenv('GCS_BUCKET_NAME')

# # login_manager = LoginManager()
# # login_manager.init_app(app)
# # login_manager.login_view = 'auth_bp.google_login'

# # CORS(
# #     app,
# #     resources={r"/*": {"origins": os.getenv('REACT_APP_FRONTEND_URL', 'http://localhost:3000')}},
# #     supports_credentials=True,
# #     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept"],
# #     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
# #     expose_headers=["Content-Length", "X-Requested-With"]
# # )

# # # --- MODIFIED: User Model to support email/password ---
# # class User(UserMixin):
# #     def __init__(self, id, email, username=None, google_id=None, profile_pic_url=None, password_hash=None):
# #         self.id = id
# #         self.email = email
# #         self.username = username if username else email.split('@')[0]
# #         self.google_id = google_id
# #         self.profile_pic_url = profile_pic_url
# #         self.password_hash = password_hash

# #     def set_password(self, password):
# #         """Creates a hash for the given password."""
# #         self.password_hash = generate_password_hash(password)

# #     def check_password(self, password):
# #         """Checks if the provided password matches the hash."""
# #         return check_password_hash(self.password_hash, password)

# #     def get_id(self):
# #         """Required by Flask-Login."""
# #         return str(self.id)

# # # --- Placeholder Database (In-memory dictionary) ---
# # # IMPORTANT: This database resets on every server restart.
# # # For production, replace this with a real database (e.g., PostgreSQL, MySQL, MongoDB).
# # _users_db = {} 

# # @login_manager.user_loader
# # def load_user(user_id):
# #     """Loads a user from the DB for Flask-Login."""
# #     return _users_db.get(user_id)

# # # --- MODIFIED: Placeholder Database Functions ---
# # def get_user_from_db(user_id=None, email=None, google_id=None):
# #     """Fetches a user from the placeholder DB."""
# #     if user_id:
# #         return _users_db.get(user_id)
# #     # Search through all users for a match by email or google_id
# #     for user in _users_db.values():
# #         if email and user.email == email:
# #             return user
# #         if google_id and user.google_id == google_id:
# #             return user
# #     return None

# # def save_user_to_db(user):
# #     """Saves a user to the placeholder DB."""
# #     _users_db[user.id] = user
# #     logger.info(f"User {user.email} saved/updated in DB. Current DB size: {len(_users_db)}")

# # # --- Other Functions (Billing, GCS) - Unchanged ---
# # def initialize_user_billing(user_id):
# #     logger.info(f"Initializing billing for user: {user_id}")

# # def get_gcs_client():
# #     return storage.Client()

# # def create_user_gcs_folders(user_email, bucket_name):
# #     logger.info(f"Creating GCS folders for user: {user_email} in bucket: {bucket_name}")
# #     try:
# #         storage_client = get_gcs_client()
# #         bucket = storage_client.bucket(bucket_name)
# #         folders_to_create = [
# #             f"{user_email}/",
# #             f"{user_email}/videos/",
# #             f"{user_email}/images/",
# #             f"{user_email}/audios/",
# #         ]
# #         for folder in folders_to_create:
# #             blob = bucket.blob(folder)
# #             if not blob.exists():
# #                 blob.upload_from_string('', content_type='application/x-directory')
# #                 logger.info(f"Created GCS folder: {folder}")
# #             else:
# #                 logger.info(f"GCS folder already exists: {folder}")
# #     except Exception as e:
# #         logger.error(f"Error creating GCS folders for {user_email}: {e}", exc_info=True)
# #         raise

# # # --- Auth Blueprint ---
# # auth_bp = Blueprint('auth_bp', __name__)

# # # --- NEW: Email/Password Registration Endpoint ---
# # @auth_bp.route('/register', methods=['POST'])
# # def register():
# #     data = request.get_json()
# #     email = data.get('email')
# #     password = data.get('password')
# #     username = data.get('username', email.split('@')[0] if email else '')

# #     if not email or not password:
# #         return jsonify(success=False, error="Email and password are required."), 400

# #     if get_user_from_db(email=email):
# #         return jsonify(success=False, error="An account with this email already exists."), 409

# #     # Create a new user
# #     new_user_id = str(uuid.uuid4()) # Generate a unique ID for the new user
# #     user = User(id=new_user_id, email=email, username=username)
# #     user.set_password(password) # Hash the password
# #     save_user_to_db(user)
    
# #     # Create GCS folders and initialize billing for the new user
# #     try:
# #         create_user_gcs_folders(email, current_app.config['GCS_BUCKET_NAME'])
# #         initialize_user_billing(user.id)
# #     except Exception as e:
# #         # If setup fails, it's better to not have a partially created user.
# #         # In a real DB, you'd roll back the transaction. Here, we remove from the dict.
# #         del _users_db[user.id]
# #         logger.error(f"Failed to set up GCS/billing for {email}. User creation rolled back.")
# #         return jsonify(success=False, error="Could not initialize user account resources."), 500

# #     login_user(user)
# #     logger.info(f"New user {email} registered and logged in successfully.")
# #     return jsonify(
# #         success=True, 
# #         message="Registration successful!",
# #         redirect_url=os.getenv('REACT_APP_FRONTEND_URL', 'http://localhost:3000') + '/dashboard',
# #         user={'email': user.email, 'name': user.username, 'picture': user.profile_pic_url}
# #     )

# # # --- NEW: Email/Password Login Endpoint ---
# # @auth_bp.route('/email_login', methods=['POST'])
# # def email_login():
# #     data = request.get_json()
# #     email = data.get('email')
# #     password = data.get('password')

# #     if not email or not password:
# #         return jsonify(success=False, error="Email and password are required."), 400

# #     user = get_user_from_db(email=email)

# #     # Check if user exists and password is correct
# #     if user and user.check_password(password):
# #         login_user(user)
# #         logger.info(f"User {email} logged in successfully via email.")
# #         return jsonify(
# #             success=True, 
# #             redirect_url=os.getenv('REACT_APP_FRONTEND_URL', 'http://localhost:3000') + '/dashboard',
# #             user={'email': user.email, 'name': user.username, 'picture': user.profile_pic_url}
# #         )
    
# #     return jsonify(success=False, error="Invalid email or password."), 401


# # # --- MODIFIED: Google Login Endpoint ---
# # @auth_bp.route('/google_login', methods=['POST'])
# # def google_login():
# #     token = request.json.get('token')
# #     if not token:
# #         return jsonify(success=False, error='No Google ID token provided'), 400
# #     try:
# #         client_id = current_app.config.get('GOOGLE_CLIENT_ID')
# #         idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), client_id)

# #         if idinfo['aud'] != client_id:
# #             raise ValueError('Audience mismatch')

# #         google_user_id = idinfo['sub']
# #         email = idinfo.get('email')
# #         name = idinfo.get('name', email.split('@')[0] if email else 'Google User')
# #         picture = idinfo.get('picture')

# #         # Check if a user with this email or Google ID already exists
# #         user = get_user_from_db(google_id=google_user_id)
# #         if not user and email:
# #             user = get_user_from_db(email=email)

# #         if user:
# #             # Existing user found. Update details and link Google ID if it's not already.
# #             user.google_id = google_user_id
# #             user.username = name
# #             user.profile_pic_url = picture
# #             save_user_to_db(user)
# #             logger.info(f"Existing user {user.email} logged in via Google.")
# #         else:
# #             # No existing user, create a new one.
# #             user = User(id=google_user_id, email=email, username=name, google_id=google_user_id, profile_pic_url=picture)
# #             save_user_to_db(user)
# #             # Set up GCS and billing for the new user
# #             create_user_gcs_folders(email, current_app.config['GCS_BUCKET_NAME'])
# #             initialize_user_billing(user.id)
# #             logger.info(f"New user {email} created via Google login.")

# #         login_user(user)
# #         return jsonify(success=True, redirect_url=os.getenv('REACT_APP_FRONTEND_URL', 'http://localhost:3000') + '/dashboard')
# #     except ValueError as e:
# #         logger.error(f"Google ID token verification failed: {e}")
# #         return jsonify(success=False, error=f'Invalid Google ID token: {e}'), 401
# #     except Exception as e:
# #         logger.error(f"Unexpected error during Google login: {e}", exc_info=True)
# #         return jsonify(success=False, error='An unexpected error occurred.'), 500

# # # --- Other Routes (Logout, Upload, etc.) - Unchanged ---
# # @auth_bp.route('/logout', methods=['POST'])
# # @login_required
# # def logout():
# #     logout_user()
# #     return jsonify(success=True, message="Logged out successfully!")

# # app.register_blueprint(auth_bp, url_prefix='/auth')

# # @app.route('/upload_file', methods=['POST'])
# # @login_required
# # def upload_file():
# #     if 'file' not in request.files:
# #         return jsonify(success=False, error='No file part'), 400
# #     file = request.files['file']
# #     if file.filename == '':
# #         return jsonify(success=False, error='No selected file'), 400
    
# #     user_email = current_user.email # Use the unified email field
# #     category = request.form.get('category', 'others')
# #     subfolder_map = {'images': 'images/', 'videos': 'videos/', 'audios': 'audios/'}
# #     subfolder = subfolder_map.get(category, '')
    
# #     filename = os.path.basename(file.filename)
# #     destination_blob_name = f"{user_email}/{subfolder}{filename}"

# #     try:
# #         bucket_name = current_app.config.get('GCS_BUCKET_NAME')
# #         storage_client = get_gcs_client()
# #         bucket = storage_client.bucket(bucket_name)
# #         blob = bucket.blob(destination_blob_name)
# #         blob.upload_from_file(file)
# #         logger.info(f"File '{filename}' uploaded to '{destination_blob_name}' by user '{user_email}'")
# #         return jsonify(success=True, message=f'File {filename} uploaded successfully.')
# #     except Exception as e:
# #         logger.error(f"Error uploading file for user {user_email}: {e}", exc_info=True)
# #         return jsonify(success=False, error=f'Failed to upload file: {e}'), 500

# # @app.route('/dashboard')
# # @login_required
# # def dashboard():
# #     return jsonify(success=True, message="Welcome to the dashboard!")

# # @app.route('/')
# # def index():
# #     if current_user.is_authenticated:
# #         return jsonify(success=True, redirect_url=os.getenv('REACT_APP_FRONTEND_URL', 'http://localhost:3000') + '/dashboard')
# #     return jsonify(success=True, redirect_url=os.getenv('REACT_APP_FRONTEND_URL', 'http://localhost:3000') + '/login')

# # if __name__ == '__main__':
# #     app.run(debug=True, port=5000)


# # backend/app.py
# from flask import Flask, request, jsonify, url_for, session, current_app, Blueprint
# from flask_login import LoginManager, login_user, current_user, login_required, UserMixin, logout_user
# from google.oauth2 import id_token
# from google.auth.transport import requests as google_requests
# from google.cloud import storage
# from flask_cors import CORS
# import os
# import logging
# from dotenv import load_dotenv
# from werkzeug.security import generate_password_hash, check_password_hash
# import uuid

# load_dotenv()

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# app = Flask(__name__)
# # We removed the explicit cookie domain to allow browser defaults for localhost.
# app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'a-very-secure-default-key-for-dev')
# app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
# app.config['GCS_BUCKET_NAME'] = os.getenv('GCS_BUCKET_NAME')

# login_manager = LoginManager()
# login_manager.init_app(app)

# @login_manager.unauthorized_handler
# def unauthorized():
#     return jsonify(success=False, error="Authorization required, please log in."), 401

# CORS(
#     app,
#     resources={r"/*": {"origins": os.getenv('REACT_APP_FRONTEND_URL', 'http://localhost:3000')}},
#     supports_credentials=True
# )

# class User(UserMixin):
#     def __init__(self, id, email, username=None, google_id=None, profile_pic_url=None, password_hash=None):
#         self.id, self.email = id, email
#         self.username = username or email.split('@')[0]
#         self.google_id, self.profile_pic_url, self.password_hash = google_id, profile_pic_url, password_hash

#     def set_password(self, password):
#         self.password_hash = generate_password_hash(password)

#     def check_password(self, password):
#         return check_password_hash(self.password_hash, password)

#     def get_id(self):
#         return str(self.id)

# _users_db = {} 

# @login_manager.user_loader
# def load_user(user_id):
#     return _users_db.get(user_id)

# def get_user_from_db(user_id=None, email=None, google_id=None):
#     if user_id: return _users_db.get(user_id)
#     for user in _users_db.values():
#         if email and user.email == email: return user
#         if google_id and user.google_id == google_id: return user
#     return None

# def save_user_to_db(user):
#     _users_db[user.id] = user

# def initialize_user_billing(user_id):
#     logger.info(f"Initializing billing for user: {user_id}")

# def get_gcs_client():
#     try:
#         credentials_path = os.path.join(os.path.dirname(__file__), 'my-credentials.json')
#         if not os.path.exists(credentials_path):
#             raise FileNotFoundError(f"CRITICAL ERROR: The credentials file 'my-credentials.json' was not found in the backend directory.")
#         return storage.Client.from_service_account_json(credentials_path)
#     except Exception as e:
#         logger.error(f"FATAL: Failed to initialize Google Cloud Storage client. Check credentials. ERROR: {e}")
#         raise

# def create_user_gcs_folders(user_email, bucket_name):
#     logger.info(f"Creating GCS folders for {user_email} in {bucket_name}")
#     try:
#         storage_client = get_gcs_client()
#         bucket = storage_client.bucket(bucket_name)
#         for folder_type in ["images", "videos", "audios"]:
#             blob = bucket.blob(f"{user_email}/{folder_type}/")
#             if not blob.exists(): blob.upload_from_string('', content_type='application/x-directory')
#     except Exception as e:
#         logger.error(f"Error creating GCS folders for {user_email}: {e}", exc_info=True)
#         raise

# auth_bp = Blueprint('auth_bp', __name__)

# @auth_bp.route('/google_login', methods=['POST'])
# def google_login():
#     token = request.json.get('token')
#     if not token: return jsonify(success=False, error='No token provided'), 400
    
#     try:
#         idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), current_app.config['GOOGLE_CLIENT_ID'])
#         email, name, picture, google_user_id = idinfo.get('email'), idinfo.get('name'), idinfo.get('picture'), idinfo['sub']

#         user = get_user_from_db(google_id=google_user_id) or get_user_from_db(email=email)

#         if user:
#             user.google_id, user.username, user.profile_pic_url = google_user_id, name, picture
#             save_user_to_db(user)
#         else:
#             user = User(id=google_user_id, email=email, username=name, google_id=google_user_id, profile_pic_url=picture)
#             save_user_to_db(user)
#             create_user_gcs_folders(email, current_app.config['GCS_BUCKET_NAME'])
#             initialize_user_billing(user.id)

#         login_user(user)
#         return jsonify(success=True, user={'email': user.email, 'name': user.username, 'picture': user.profile_pic_url})
#     except Exception as e:
#         logger.error(f"Error during Google login: {e}", exc_info=True)
#         return jsonify(success=False, error='Server error during Google Login.'), 500

# @auth_bp.route('/logout', methods=['POST'])
# @login_required
# def logout():
#     logout_user()
#     return jsonify(success=True, message="Logged out successfully!")

# app.register_blueprint(auth_bp, url_prefix='/auth')

# @app.route('/upload_file', methods=['POST'])
# @login_required
# def upload_file():
#     if 'file' not in request.files: return jsonify(success=False, error='No file part'), 400
#     file = request.files['file']
#     if file.filename == '': return jsonify(success=False, error='No selected file'), 400
    
#     user_email = current_user.email
#     category = request.form.get('category', 'others')
#     subfolder = {'images': 'images/', 'videos': 'videos/', 'audios': 'audios/'}.get(category, '')
    
#     filename = os.path.basename(file.filename)
#     destination_blob_name = f"{user_email}/{subfolder}{filename}"

#     try:
#         bucket_name = current_app.config['GCS_BUCKET_NAME']
#         storage_client = get_gcs_client()
#         blob = storage_client.bucket(bucket_name).blob(destination_blob_name)
#         blob.upload_from_file(file)
#         return jsonify(success=True, message=f'File {filename} uploaded successfully.')
#     except Exception as e:
#         logger.error(f"Error uploading file for user {user_email}: {e}", exc_info=True)
#         return jsonify(success=False, error=f'Failed to upload file: {e}'), 500

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5000)



# # backend/app.py
# from flask import Flask, request, jsonify, Blueprint, current_app
# from flask_cors import CORS
# import os
# import logging
# from dotenv import load_dotenv
# from werkzeug.security import generate_password_hash, check_password_hash
# import uuid

# # --- NEW: Import JWT libraries ---
# from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager

# from google.oauth2 import id_token
# from google.auth.transport import requests as google_requests
# from google.cloud import storage

# # --- Setup ---
# load_dotenv()
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)
# app = Flask(__name__)

# # --- NEW: Configuration for JWT ---
# # IMPORTANT: Make sure you have a JWT_SECRET_KEY in your .env file
# app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY', "a-default-super-secret-jwt-key-for-dev")
# jwt = JWTManager(app)

# # --- Other Configurations ---
# app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
# app.config['GCS_BUCKET_NAME'] = os.getenv('GCS_BUCKET_NAME')

# # --- CORS Configuration ---
# # This allows your frontend to communicate with your backend
# CORS(app, resources={r"/*": {"origins": os.getenv('REACT_APP_FRONTEND_URL', 'http://localhost:3000')}}, supports_credentials=True)


# # --- User Model and DB ---
# class User():
#     """A simple User model."""
#     def __init__(self, id, email, username=None, google_id=None, profile_pic_url=None, password_hash=None):
#         self.id = id
#         self.email = email
#         self.username = username or email.split('@')[0]
#         self.google_id = google_id
#         self.profile_pic_url = profile_pic_url
#         self.password_hash = password_hash
    
#     def set_password(self, password):
#         self.password_hash = generate_password_hash(password)

#     def check_password(self, password):
#         return check_password_hash(self.password_hash, password)

# # Using an in-memory dictionary as a placeholder for a real database
# _users_db = {} 

# # --- JWT User Loader ---
# # This function is called whenever a protected endpoint is accessed,
# # and it loads the user object from the database based on the token's identity.
# @jwt.user_lookup_loader
# def user_lookup_callback(_jwt_header, jwt_data):
#     """This function is called to get the user object from the JWT payload."""
#     identity = jwt_data["sub"]
#     return get_user_from_db(user_id=identity)

# # --- Database Helper Functions ---
# def get_user_from_db(user_id=None, email=None, google_id=None):
#     """Fetches a user from the placeholder DB."""
#     if user_id: return _users_db.get(user_id)
#     for user in _users_db.values():
#         if email and user.email == email: return user
#         if google_id and user.google_id == google_id: return user
#     return None

# def save_user_to_db(user):
#     """Saves a user to the placeholder DB."""
#     _users_db[user.id] = user
#     logger.info(f"User {user.email} saved/updated in DB.")


# # --- Google Cloud Storage Helper Functions ---
# def get_gcs_client():
#     """Initializes the GCS client using credentials file."""
#     try:
#         credentials_path = os.path.join(os.path.dirname(__file__), 'my-credentials.json')
#         if not os.path.exists(credentials_path):
#             raise FileNotFoundError(f"CRITICAL ERROR: 'my-credentials.json' not found in the backend directory.")
#         return storage.Client.from_service_account_json(credentials_path)
#     except Exception as e:
#         logger.error(f"FATAL: GCS client failed to initialize. Check credentials file. ERROR: {e}")
#         raise

# def create_user_gcs_folders(user_email, bucket_name):
#     """Creates initial folders for a new user in GCS."""
#     logger.info(f"Creating GCS folders for {user_email} in {bucket_name}")
#     try:
#         storage_client = get_gcs_client()
#         bucket = storage_client.bucket(bucket_name)
#         for folder_type in ["images", "videos", "audios", "others"]:
#             blob = bucket.blob(f"{user_email}/{folder_type}/")
#             if not blob.exists(): 
#                 blob.upload_from_string('', content_type='application/x-directory')
#     except Exception as e:
#         logger.error(f"Failed to create GCS folders for {user_email}: {e}", exc_info=True)
#         raise

# def initialize_user_billing(user_id):
#     """Placeholder function for billing logic."""
#     logger.info(f"Placeholder: Initializing billing for user: {user_id}")


# # --- Authentication Routes ---
# auth_bp = Blueprint('auth_bp', __name__)

# @auth_bp.route('/google_login', methods=['POST'])
# def google_login():
#     """Handles user login via Google and returns a JWT."""
#     token = request.json.get('token')
#     if not token:
#         return jsonify(success=False, error="No token provided"), 400
        
#     try:
#         idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), current_app.config['GOOGLE_CLIENT_ID'])
#         email, name, picture = idinfo.get('email'), idinfo.get('name'), idinfo.get('picture')
#         google_user_id = idinfo['sub']
        
#         user = get_user_from_db(google_id=google_user_id) or get_user_from_db(email=email)

#         if not user:
#             logger.info(f"Creating new user for {email}")
#             user = User(id=google_user_id, email=email, username=name, google_id=google_user_id, profile_pic_url=picture)
#             save_user_to_db(user)
#             create_user_gcs_folders(email, current_app.config['GCS_BUCKET_NAME'])
#             initialize_user_billing(user.id)
        
#         # Create a new token for the user
#         access_token = create_access_token(identity=user.id)
#         return jsonify(
#             success=True, 
#             user={'email': user.email, 'name': user.username, 'picture': user.profile_pic_url},
#             access_token=access_token # This is the key that the frontend needs
#         )
#     except Exception as e:
#         logger.error(f"Error during Google login: {e}", exc_info=True)
#         return jsonify(success=False, error='Server error during Google Login.'), 500

# app.register_blueprint(auth_bp, url_prefix='/auth')


# # --- Protected File Upload Route ---
# @app.route('/upload_file', methods=['POST'])
# @jwt_required() # This decorator protects the route, ensuring a valid token is present
# def upload_file():
#     """Handles file uploads for authenticated users."""
#     user_id = get_jwt_identity() # Get user's ID from the token
#     current_user = get_user_from_db(user_id=user_id)
#     if not current_user:
#         return jsonify(success=False, error="User not found in database."), 404

#     if 'file' not in request.files: 
#         return jsonify(success=False, error='No file part in the request'), 400
        
#     file = request.files['file']
#     if file.filename == '':
#         return jsonify(success=False, error='No selected file'), 400
    
#     user_email = current_user.email
#     category = request.form.get('category', 'others')
#     # Ensure a trailing slash for folder structure
#     subfolder = {'images': 'images/', 'videos': 'videos/', 'audios': 'audios/'}.get(category, 'others/')
    
#     filename = os.path.basename(file.filename) # Sanitize filename
#     destination_blob_name = f"{user_email}/{subfolder}{filename}"

#     try:
#         storage_client = get_gcs_client()
#         blob = storage_client.bucket(current_app.config['GCS_BUCKET_NAME']).blob(destination_blob_name)
#         blob.upload_from_file(file)
#         logger.info(f"File '{filename}' uploaded to '{destination_blob_name}' by user '{user_email}'.")
#         return jsonify(success=True, message=f'File {filename} uploaded successfully.')
#     except Exception as e:
#         logger.error(f"Error uploading file for user {user_email}: {e}", exc_info=True)
#         return jsonify(success=False, error='Failed to upload file due to a server error.'), 500


# # --- Main Entry Point ---
# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5000)

# backend/app.py
from flask import Flask, request, jsonify, Blueprint, current_app
from flask_cors import CORS
import os
import logging
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

# --- NEW: Import JWT libraries ---
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google.cloud import storage

# --- Setup ---
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = Flask(__name__)

# --- NEW: Configuration for JWT ---
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY', "a-default-super-secret-jwt-key-for-dev")
jwt = JWTManager(app)

# --- Other Configurations ---
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GCS_BUCKET_NAME'] = os.getenv('GCS_BUCKET_NAME')

# --- CORS Configuration ---
CORS(app, resources={r"/*": {"origins": os.getenv('REACT_APP_FRONTEND_URL', 'http://localhost:3000')}}, supports_credentials=True)


# --- User Model and DB ---
class User():
    def __init__(self, id, email, username=None, google_id=None, profile_pic_url=None, password_hash=None):
        self.id = id
        self.email = email
        self.username = username or email.split('@')[0]
        self.google_id = google_id
        self.profile_pic_url = profile_pic_url
        self.password_hash = password_hash
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

_users_db = {} 

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return get_user_from_db(user_id=identity)

def get_user_from_db(user_id=None, email=None, google_id=None):
    if user_id: return _users_db.get(user_id)
    for user in _users_db.values():
        if email and user.email == email: return user
        if google_id and user.google_id == google_id: return user
    return None

def save_user_to_db(user):
    _users_db[user.id] = user
    logger.info(f"User {user.email} saved/updated in DB.")


# --- Google Cloud Storage Helper Functions ---
def get_gcs_client():
    try:
        credentials_path = os.path.join(os.path.dirname(__file__), 'my-credentials.json')
        if not os.path.exists(credentials_path):
            raise FileNotFoundError(f"CRITICAL ERROR: 'my-credentials.json' not found in the backend directory.")
        return storage.Client.from_service_account_json(credentials_path)
    except Exception as e:
        logger.error(f"FATAL: GCS client failed to initialize. Check credentials file. ERROR: {e}")
        raise

def create_user_gcs_folders(user_email, bucket_name):
    logger.info(f"Creating GCS folders for {user_email} in {bucket_name}")
    try:
        storage_client = get_gcs_client()
        bucket = storage_client.bucket(bucket_name)
        for folder_type in ["images", "videos", "audios", "others"]:
            blob = bucket.blob(f"{user_email}/{folder_type}/")
            if not blob.exists(): 
                blob.upload_from_string('', content_type='application/x-directory')
    except Exception as e:
        logger.error(f"Failed to create GCS folders for {user_email}: {e}", exc_info=True)
        raise

def initialize_user_billing(user_id):
    logger.info(f"Placeholder: Initializing billing for user: {user_id}")


# --- Authentication Routes ---
auth_bp = Blueprint('auth_bp', __name__)

@auth_bp.route('/google_login', methods=['POST'])
def google_login():
    token = request.json.get('token')
    if not token:
        return jsonify(success=False, error="No token provided"), 400
        
    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), current_app.config['GOOGLE_CLIENT_ID'])
        email, name, picture = idinfo.get('email'), idinfo.get('name'), idinfo.get('picture')
        google_user_id = idinfo['sub']
        
        user = get_user_from_db(google_id=google_user_id) or get_user_from_db(email=email)

        if not user:
            logger.info(f"Creating new user for {email}")
            user = User(id=google_user_id, email=email, username=name, google_id=google_user_id, profile_pic_url=picture)
            save_user_to_db(user)
            create_user_gcs_folders(email, current_app.config['GCS_BUCKET_NAME'])
            initialize_user_billing(user.id)
        
        access_token = create_access_token(identity=user.id)
        return jsonify(
            success=True, 
            user={'email': user.email, 'name': user.username, 'picture': user.profile_pic_url},
            access_token=access_token
        )
    except Exception as e:
        logger.error(f"Error during Google login: {e}", exc_info=True)
        return jsonify(success=False, error='Server error during Google Login.'), 500

app.register_blueprint(auth_bp, url_prefix='/auth')


# --- Protected File Upload Route ---
@app.route('/upload_file', methods=['POST'])
@jwt_required()
def upload_file():
    user_id = get_jwt_identity()
    current_user = get_user_from_db(user_id=user_id)
    if not current_user:
        return jsonify(success=False, error="User not found in database."), 404

    if 'file' not in request.files: 
        return jsonify(success=False, error='No file part in the request'), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, error='No selected file'), 400
    
    try:
        user_email = current_user.email
        category = request.form.get('category', 'others')
        subfolder = {'images': 'images/', 'videos': 'videos/', 'audios': 'audios/'}.get(category, 'others/')
        
        filename = os.path.basename(file.filename)
        destination_blob_name = f"{user_email}/{subfolder}{filename}"

        # --- ENHANCED LOGGING ---
        logger.info("Attempting to get GCS client...")
        storage_client = get_gcs_client()
        
        logger.info(f"Attempting to access bucket: {current_app.config['GCS_BUCKET_NAME']}")
        bucket = storage_client.bucket(current_app.config['GCS_BUCKET_NAME'])
        
        logger.info(f"Attempting to upload to blob: {destination_blob_name}")
        blob = bucket.blob(destination_blob_name)
        blob.upload_from_file(file)

        logger.info(f"File '{filename}' uploaded successfully by user '{user_email}'.")
        return jsonify(success=True, message=f'File {filename} uploaded successfully.')

    except Exception as e:
        # This will now catch any error and log it, then return a specific message
        logger.error(f"An unexpected error occurred during file upload for user {current_user.email}: {e}", exc_info=True)
        return jsonify(success=False, error=f'Server-side error: {e}'), 500


# --- Main Entry Point ---
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
