from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image, ImageEnhance, ImageFilter
import pytesseract
import re
import os
import random
import string
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import phonenumbers
from email_validator import validate_email, EmailNotValidError
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
import google.generativeai as genai
import uuid

# Load environment variables
load_dotenv()

app = Flask(__name__)
# Configure CORS to allow all origins and methods
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:5173"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type"],
        "supports_credentials": True,
        "max_age": 120  # Cache preflight requests for 2 minutes
    }
})

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['JWT_EXPIRATION_HOURS'] = 24
app.config['UPLOAD_FOLDER'] = "static/uploads"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize MongoDB
mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
client = MongoClient(mongo_uri)
db = client['enam_db']
farmers_collection = db['farmers']
merchants_collection = db['merchants']
otp_collection = db['otp']
orders_collection = db['orders']

# Initialize OCR
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Initialize Gemini
genai.configure(api_key='AIzaSyDCFWWUflw_h5AkGmVkR-3Dqey1DS1BJOg')
model = genai.GenerativeModel('gemini-pro')

# Helper functions
def generate_unique_username(business_name):
    base = ''.join(e for e in business_name if e.isalnum()).lower()
    while True:
        suffix = ''.join(random.choices(string.digits, k=4))
        username = f"{base}{suffix}"
        if not merchants_collection.find_one({"username": username}):
            return username

def validate_phone_number(phone_number):
    try:
        parsed = phonenumbers.parse(phone_number, "IN")
        return phonenumbers.is_valid_number(parsed)
    except phonenumbers.phonenumberutil.NumberParseException:
        return False

def validate_email_address(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def create_jwt_token(user_data):
    expiration = datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
    token = jwt.encode(
        {**user_data, 'exp': expiration},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return token

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def preprocess_image(image_path):
    image = Image.open(image_path).convert("L")  # Convert to grayscale
    image = ImageEnhance.Contrast(image).enhance(2)  # Increase contrast
    image = image.filter(ImageFilter.SHARPEN)  # Sharpen image
    return image

def extract_details(image_path):
    image = preprocess_image(image_path)
    extracted_text = pytesseract.image_to_string(image)

    # Name pattern
    name_pattern = re.search(r"(?:To\s+)?([A-Z][a-z]+\s[A-Z][a-z]+\s[A-Z][a-z]+)", extracted_text)

    # Date of Birth pattern (Handling different formats like "DOB:", "D.O.B:", "Date of Birth:")
    dob_pattern = re.search(r"(?:DOB|D\.O\.B|Date\s*of\s*Birth)[:\s]*(\d{2}/\d{2}/\d{4})", extracted_text)

    # Gender pattern
    gender_pattern = re.search(r"\b(Male|Female|Other)\b", extracted_text, re.IGNORECASE)

    # Aadhaar Number pattern
    aadhaar_pattern = re.search(r"\b\d{4}\s\d{4}\s\d{4}\b", extracted_text)

    # VID Number pattern (Handling different formats like "VID:", "Virtual ID:")
    vid_pattern = re.search(r"(?:VID|Virtual\s*ID)[:\s]*(\d{4}\s\d{4}\s\d{4}\s\d{4})", extracted_text)

    # Phone Number pattern
    phone_pattern = re.search(r"Mobile:\s*(\d{10})", extracted_text)

    # Pincode pattern
    pincode_pattern = re.search(r"(?:PIN\s*Code[:\s]*)?(\d{6})", extracted_text)

    # Address Extraction with More Keywords
    address_keywords = [
        "H NO", "House No", "Street", "Road", "Near", "Village", "Post", "District", "Mandal",
        "Sub District", "State", "PO", "VTC", "Urban", "Locality", "Town", "Tehsil"
    ]

    # Expanded list of Indian States for better recognition
    states = [
        "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh", "Goa", "Gujarat",
        "Haryana", "Himachal Pradesh", "Jharkhand", "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra",
        "Manipur", "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Punjab", "Rajasthan", "Sikkim", "Tamil Nadu",
        "Telangana", "Tripura", "Uttar Pradesh", "Uttarakhand", "West Bengal"
    ]

    address_lines = []
    for line in extracted_text.split("\n"):
        if any(keyword in line for keyword in address_keywords) or any(state in line for state in states):
            address_lines.append(line.strip())

    address = " ".join(address_lines)

    # Store extracted details
    details = {
        "name": name_pattern.group(1) if name_pattern else "",
        "dob": dob_pattern.group(1) if dob_pattern else "",
        "gender": gender_pattern.group(1).lower() if gender_pattern else "",
        "address": address if address else "",
        "pincode": pincode_pattern.group(1) if pincode_pattern else "",
        "aadhaar": aadhaar_pattern.group(0).replace(" ", "") if aadhaar_pattern else "",
        "vid": vid_pattern.group(1).replace(" ", "") if vid_pattern else "",
        "mobile": phone_pattern.group(1) if phone_pattern else ""
    }

    print("Extracted Details:", details)  # Printing extracted details

    return details

# Default QA pairs in Telugu
default_qa = {
    'ధరలు': 'ప్రస్తుత మార్కెట్ ధరలు:\nవరి: ₹2200/క్వింటాల్\nగోధుమ: ₹2400/క్వింటాల్\nమొక్కజొన్న: ₹1800/క్వింటాల్\nకందులు: ₹8500/క్వింటాల్',
    'వాతావరణం': 'నేటి వాతావరణం:\nఉష్ణోగ్రత: 28°C\nఆకాశం: ఎండగా ఉంటుంది\nవర్షపాతం: లేదు',
    'మార్కెట్': 'మార్కెట్ పరిస్థితి:\nవరి, గోధుమలకు మంచి డిమాండ్ ఉంది\nధరలు స్థిరంగా ఉన్నాయి\nకొనుగోలు చేయడానికి మంచి సమయం',
    'పంటలు': 'ఈ సీజన్ కి అనువైన పంటలు:\n1. వరి\n2. మొక్కజొన్న\n3. కందులు\n4. వేరుశనగ',
    'సహాయం': 'నేను మీకు ఈ విషయాలలో సహాయం చేయగలను:\n1. పంట ధరల సమాచారం\n2. వాతావరణ సమాచారం\n3. మార్కెట్ ట్రెండ్స్\n4. పంటల సలహాలు'
}

# Market insights data (in a real app, this would come from a database)
market_insights = [
    {
        'id': 1,
        'message': 'వరి ధరలు 10% పెరిగాయి',
        'category': 'price'
    },
    {
        'id': 2,
        'message': 'పప్పు ధాన్యాలకు డిమాండ్ పెరుగుతోంది',
        'category': 'demand'
    },
    {
        'id': 3,
        'message': 'వచ్చే వారం వర్షం పడే అవకాశం ఉంది',
        'category': 'weather'
    },
    {
        'id': 4,
        'message': 'మిరప ధరలు స్థిరంగా ఉన్నాయి',
        'category': 'price'
    },
    {
        'id': 5,
        'message': 'పండ్ల ఎగుమతులు పెరుగుతున్నాయి',
        'category': 'demand'
    }
]

@app.route('/register/farmer', methods=['POST'])
def register_farmer():
    print("Received farmer registration request")  # Debug log
    data = request.json
    print("Request data:", data)  # Debug log
    
    required_fields = ['name', 'phoneNumber', 'password', 'address']
    
    if not all(field in data for field in required_fields):
        missing_fields = [field for field in required_fields if field not in data]
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    if not validate_phone_number(data['phoneNumber']):
        return jsonify({'error': 'Invalid phone number'}), 400

    if farmers_collection.find_one({'phoneNumber': data['phoneNumber']}):
        return jsonify({'error': 'Phone number already registered'}), 400

    farmer_data = {
        'name': data['name'],
        'phoneNumber': data['phoneNumber'],
        'password': generate_password_hash(data['password']),
        'address': data['address'],
        'currentCrops': [],
        'futureCrops': [],
        'notifications': [],  # Initialize empty notifications array
        'createdAt': datetime.utcnow()
    }

    try:
        result = farmers_collection.insert_one(farmer_data)
        print("Farmer registered successfully:", result.inserted_id)  # Debug log
        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        print("Error registering farmer:", str(e))  # Debug log
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/register/merchant', methods=['POST'])
def register_merchant():
    print("Received merchant registration request")  # Debug log
    data = request.json
    print("Request data:", data)  # Debug log
    
    required_fields = ['name', 'businessName', 'password', 'businessAddress', 'phoneNumber']
    
    if not all(field in data for field in required_fields):
        missing_fields = [field for field in required_fields if field not in data]
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    # Validate phone number
    if not validate_phone_number(data['phoneNumber']):
        return jsonify({'error': 'Invalid phone number format'}), 400

    # Check if phone number already exists
    if merchants_collection.find_one({"phoneNumber": data['phoneNumber']}):
        return jsonify({'error': 'Phone number already registered'}), 400

    username = generate_unique_username(data['businessName'])
    
    merchant_data = {
        'name': data['name'],
        'businessName': data['businessName'],
        'username': username,
        'password': generate_password_hash(data['password']),
        'address': data['businessAddress'],
        'phoneNumber': data['phoneNumber'],
        'notifications': [],  # Initialize empty notifications array
        'createdAt': datetime.utcnow()
    }

    try:
        result = merchants_collection.insert_one(merchant_data)
        print("Merchant registered successfully:", result.inserted_id)  # Debug log
        return jsonify({
            'message': 'Registration successful',
            'username': username
        }), 201
    except Exception as e:
        print("Error registering merchant:", str(e))  # Debug log
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.json
    phone_number = data.get('phoneNumber')
    print("Phone number from request:", phone_number)  # Debug log
    
    if not phone_number:
        return jsonify({"error": "Phone number is required"}), 400
            
    try:
        validate_phone_number(phone_number)
    except ValueError as e:
        print("Phone number validation error:", str(e))  # Debug log
        return jsonify({"error": str(e)}), 400
        
    # Generate and store OTP
    otp = generate_otp()
    print("Generated OTP:", otp)  # Debug log
    
    # Delete any existing OTPs for this phone number
    delete_result = otp_collection.delete_many({'phoneNumber': phone_number})
    print("Deleted existing OTPs:", delete_result.deleted_count)  # Debug log
    
    # Store new OTP
    expiry_time = datetime.utcnow() + timedelta(minutes=10)
    otp_data = {
        'phoneNumber': phone_number,
        'otp': otp,
        'attempts': 0,
        'verified': False,
        'expiresAt': expiry_time
    }
    
    try:
        result = otp_collection.insert_one(otp_data)
        print("Stored new OTP with ID:", result.inserted_id)  # Debug log
    except Exception as e:
        print("Error storing OTP:", str(e))  # Debug log
        return jsonify({"error": "Failed to store OTP"}), 500
        
    # In production, integrate with SMS service
    print(f"OTP for {phone_number}: {otp}")
    print(f"OTP will expire at: {expiry_time}")  # Debug log
        
    return jsonify({"message": "OTP sent successfully"}), 200

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    phone_number = data.get('phoneNumber')
    submitted_otp = data.get('otp')
        
    if not phone_number or not submitted_otp:
        return jsonify({"error": "Phone number and OTP are required"}), 400
            
    stored_data = otp_collection.find_one({'phoneNumber': phone_number})
    if not stored_data:
        return jsonify({"error": "No OTP found for this number"}), 400
            
    # Check OTP expiration
    if datetime.utcnow() > stored_data['expiresAt']:
        otp_collection.delete_one({'phoneNumber': phone_number})
        return jsonify({"error": "OTP has expired"}), 400
            
    # Check attempts
    stored_data['attempts'] += 1
    if stored_data['attempts'] > 3:
        otp_collection.delete_one({'phoneNumber': phone_number})
        return jsonify({"error": "Too many attempts. Please request a new OTP"}), 400
            
    if submitted_otp != stored_data['otp']:
        return jsonify({"error": "Invalid OTP"}), 400
            
    # Clear OTP after successful verification
    otp_collection.delete_one({'phoneNumber': phone_number})
        
    return jsonify({"message": "OTP verified successfully"}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    print("Login request data:", data)  # Debug log
    
    if 'userType' not in data:
        return jsonify({'error': 'User type is required'}), 400
        
    if data['userType'] == 'merchant':
        if not all(k in data for k in ['username', 'password']):
            return jsonify({'error': 'Username and password are required for merchant login'}), 400
            
        user = merchants_collection.find_one({'username': data['username']})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        if not check_password_hash(user['password'], data['password']):
            return jsonify({'error': 'Invalid password'}), 401
            
    else:  # farmer login
        if not all(k in data for k in ['phoneNumber', 'otp']):
            missing = [k for k in ['phoneNumber', 'otp'] if k not in data]
            return jsonify({'error': f'Missing required fields: {", ".join(missing)}'}), 400
            
        print("Searching for OTP with phone number:", data['phoneNumber'])  # Debug log
        print("Submitted OTP:", data['otp'])  # Debug log
            
        # Verify OTP
        otp_record = otp_collection.find_one({
            'phoneNumber': data['phoneNumber'],
            'otp': data['otp'],
            'verified': False,
            'expiresAt': {'$gt': datetime.utcnow()}
        })
        
        print("Found OTP record:", otp_record)  # Debug log
        
        if not otp_record:
            # Check if OTP exists but expired
            expired_otp = otp_collection.find_one({
                'phoneNumber': data['phoneNumber'],
                'otp': data['otp'],
                'verified': False
            })
            if expired_otp:
                print("Found expired OTP:", expired_otp)  # Debug log
                return jsonify({'error': 'OTP has expired. Please request a new one'}), 401
            return jsonify({'error': 'Invalid OTP'}), 401
            
        user = farmers_collection.find_one({'phoneNumber': data['phoneNumber']})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        # Mark OTP as verified
        otp_collection.update_one(
            {'_id': otp_record['_id']},
            {'$set': {'verified': True}}
        )

    # Prepare user data for token
    user_data = {
        'id': str(user['_id']),
        'type': data['userType'],
        'name': user['name']
    }
    
    if data['userType'] == 'merchant':
        user_data.update({
            'username': user['username'],
            'businessName': user['businessName']
        })
    else:
        user_data['phoneNumber'] = user['phoneNumber']

    token = create_jwt_token(user_data)
    
    return jsonify({
        'token': token,
        'user': user_data
    }), 200

@app.route('/farmer/<phone_number>/crops', methods=['POST'])
def add_crop(phone_number):
    data = request.json
    if not all(k in data for k in ['cropId', 'quantity']):
        return jsonify({'error': 'Missing required fields'}), 400

    result = farmers_collection.update_one(
        {'phoneNumber': phone_number},
        {'$push': {'currentCrops': {
            'cropId': data['cropId'],
            'quantity': data['quantity']
        }}}
    )

    if result.modified_count:
        return jsonify({'message': 'Crop added successfully'}), 200
    else:
        return jsonify({'error': 'Failed to add crop'}), 500

@app.route('/farmer/<phone_number>/future-crops', methods=['PUT'])
def update_future_crops(phone_number):
    data = request.json
    if 'futureCrops' not in data:
        return jsonify({'error': 'Missing future crops data'}), 400

    result = farmers_collection.update_one(
        {'phoneNumber': phone_number},
        {'$set': {'futureCrops': data['futureCrops']}}
    )

    if result.modified_count:
        return jsonify({'message': 'Future crops updated successfully'}), 200
    else:
        return jsonify({'error': 'Failed to update future crops'}), 500

@app.route('/farmers', methods=['GET'])
def get_farmers():
    farmers = list(farmers_collection.find({}, {
        'password': 0,
        '_id': 0
    }))
    return jsonify(farmers), 200

@app.route('/merchants', methods=['GET'])
def get_merchants():
    merchants = list(merchants_collection.find({}, {
        'password': 0,
        '_id': 0
    }))
    return jsonify(merchants), 200

@app.route('/user/<user_type>/<identifier>', methods=['GET'])
def get_user(user_type, identifier):
    collection = farmers_collection if user_type == 'farmer' else merchants_collection
    identifier_field = 'phoneNumber' if user_type == 'farmer' else 'username'
    
    user = collection.find_one({identifier_field: identifier}, {'password': 0})
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    user['_id'] = str(user['_id'])
    return jsonify(user), 200

@app.route('/upload', methods=['POST'])
def upload():
    print("Received file upload request")  # Debug log
    
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Check file extension
    allowed_extensions = {'png', 'jpg', 'jpeg'}
    if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({"error": "Invalid file type. Only PNG and JPEG images are allowed"}), 400

    try:
        # Generate a secure filename
        filename = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        filename += '.' + file.filename.rsplit('.', 1)[1].lower()
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        print(f"File saved successfully at: {filepath}")  # Debug log
        
        # Extract details from the image
        try:
            extracted_data = extract_details(filepath)
            return jsonify(extracted_data), 200
        except Exception as e:
            print(f"Error extracting details: {str(e)}")  # Debug log
            return jsonify({"error": f"Failed to process image: {str(e)}"}), 500
            
    except Exception as e:
        print(f"Error saving file: {str(e)}")  # Debug log
        return jsonify({"error": f"Failed to save file: {str(e)}"}), 500

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    message = data.get('message', '').lower()
    
    if not message:
        return jsonify({'error': 'No message provided'}), 400

    try:
        # Check for default questions
        for key, value in default_qa.items():
            if key in message:
                return jsonify({
                    'response': value,
                    'suggestions': list(default_qa.keys())
                }), 200

        # If not a default question, use Gemini to generate response in Telugu
        context = """You are an AI assistant for the Electronic National Agriculture Market (e-NAM) platform.
        Provide responses in Telugu script (not transliterated).
        Focus on:
        1. Agricultural market information
        2. Crop prices and trends
        3. Weather updates
        4. Farming best practices
        5. Government schemes
        Keep responses concise and farmer-friendly."""

        prompt = f"{context}\n\nUser: {message}\nAssistant:"
        response = model.generate_content(prompt)
        
        return jsonify({
            'response': response.text,
            'suggestions': list(default_qa.keys())
        }), 200

    except Exception as e:
        print("Error in chat endpoint:", str(e))
        return jsonify({
            'error': 'Failed to generate response',
            'suggestions': list(default_qa.keys())
        }), 500

@app.route('/order', methods=['POST'])
def create_order():
    data = request.json
    merchant_username = data.get('merchantUsername')
    farmer_phone = data.get('farmerPhone')
    crop_id = data.get('cropId')
    quantity = data.get('quantity')
    
    try:
        # Get merchant and farmer details
        merchant = merchants_collection.find_one({'username': merchant_username})
        farmer = farmers_collection.find_one({'phoneNumber': farmer_phone})
        
        if not merchant or not farmer:
            return jsonify({'error': 'Merchant or farmer not found'}), 404
            
        # Create order
        order = {
            'merchantId': str(merchant['_id']),
            'farmerId': str(farmer['_id']),
            'merchantName': merchant['name'],
            'farmerName': farmer['name'],
            'merchantUsername': merchant_username,
            'farmerPhone': farmer_phone,
            'cropId': crop_id,
            'quantity': quantity,
            'status': 'pending',
            'createdAt': datetime.utcnow()
        }
        
        result = orders_collection.insert_one(order)
        
        # Send notification message to farmer
        notification = {
            'id': str(result.inserted_id),
            'type': 'order_request',
            'message': f"{merchant['name']} వారు మీ వద్ద {quantity} కిలోల {crop_id} కొనుగోలు చేయాలనుకుంటున్నారు.",
            'timestamp': datetime.utcnow(),
            'status': 'pending',
            'data': {
                'orderId': str(result.inserted_id),
                'merchantUsername': merchant_username,
                'cropId': crop_id,
                'quantity': quantity
            }
        }
        
        farmers_collection.update_one(
            {'phoneNumber': farmer_phone},
            {'$push': {'notifications': notification}}
        )
        
        return jsonify({
            'message': 'Order request sent successfully',
            'orderId': str(result.inserted_id)
        }), 201
        
    except Exception as e:
        print("Error creating order:", str(e))
        return jsonify({'error': 'Failed to create order'}), 500

@app.route('/order/<order_id>/accept', methods=['POST'])
def accept_order(order_id):
    try:
        # Find the order
        order = orders_collection.find_one({'_id': ObjectId(order_id)})
        if not order:
            return jsonify({'error': 'Order not found'}), 404

        # Update order status
        orders_collection.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': {'status': 'accepted'}}
        )

        # Update notification status
        farmers_collection.update_one(
            {'phoneNumber': order['farmerPhone'], 'notifications.id': order_id},
            {'$set': {
                'notifications.$.status': 'accepted'
            }}
        )

        # Add merchant to farmer's connected merchants
        farmers_collection.update_one(
            {'phoneNumber': order['farmerPhone']},
            {'$addToSet': {'connectedMerchants': order['merchantUsername']}}
        )

        # Add farmer to merchant's connected farmers
        merchants_collection.update_one(
            {'username': order['merchantUsername']},
            {'$addToSet': {'connectedFarmers': order['farmerPhone']}}
        )

        # Add notification for merchant
        merchant_notification = {
            'message': f"{order['farmerName']} వారు మీ ఆర్డర్ ను అంగీకరించారు.",
            'timestamp': datetime.utcnow(),
            'type': 'order_accepted',
            'status': 'unread'
        }

        merchants_collection.update_one(
            {'username': order['merchantUsername']},
            {'$push': {'notifications': merchant_notification}}
        )

        return jsonify({'message': 'Order accepted successfully'}), 200

    except Exception as e:
        print("Error accepting order:", str(e))
        return jsonify({'error': 'Failed to accept order'}), 500

@app.route('/order/<order_id>/reject', methods=['POST'])
def reject_order(order_id):
    try:
        # Find the order
        order = orders_collection.find_one({'_id': ObjectId(order_id)})
        if not order:
            return jsonify({'error': 'Order not found'}), 404

        # Update order status
        orders_collection.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': {'status': 'rejected'}}
        )

        # Update notification status
        farmers_collection.update_one(
            {'phoneNumber': order['farmerPhone'], 'notifications.id': order_id},
            {'$set': {
                'notifications.$.status': 'rejected'
            }}
        )

        # Add notification for merchant
        merchant_notification = {
            'message': f"{order['farmerName']} వారు మీ ఆర్డర్ ను తిరస్కరించారు.",
            'timestamp': datetime.utcnow(),
            'type': 'order_rejected',
            'status': 'unread'
        }

        merchants_collection.update_one(
            {'username': order['merchantUsername']},
            {'$push': {'notifications': merchant_notification}}
        )

        return jsonify({'message': 'Order rejected successfully'}), 200

    except Exception as e:
        print("Error rejecting order:", str(e))
        return jsonify({'error': 'Failed to reject order'}), 500

@app.route('/farmer/<phone>/notifications', methods=['GET'])
def get_farmer_notifications(phone):
    try:
        farmer = farmers_collection.find_one({'phoneNumber': phone})
        if not farmer:
            return jsonify({'error': 'Farmer not found'}), 404
            
        notifications = farmer.get('notifications', [])
        return jsonify({'notifications': notifications}), 200
        
    except Exception as e:
        print("Error fetching notifications:", str(e))
        return jsonify({'error': 'Failed to fetch notifications'}), 500

@app.route('/merchant/<username>/notifications', methods=['GET'])
def get_merchant_notifications(username):
    try:
        # Find merchant and handle if not found
        merchant = merchants_collection.find_one({'username': username})
        if not merchant:
            return jsonify({'error': 'Merchant not found'}), 404
            
        # Get notifications array or empty list if none exist
        notifications = merchant.get('notifications', [])
        
        # Convert ObjectId to string for JSON serialization
        for notification in notifications:
            if '_id' in notification:
                notification['_id'] = str(notification['_id'])
            # Ensure all required fields exist
            notification.setdefault('id', str(uuid.uuid4()))
            notification.setdefault('status', 'unread')
            notification.setdefault('timestamp', datetime.now().isoformat())
        
        # Sort notifications by timestamp, newest first
        notifications.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Mark notifications as read
        if notifications:
            merchants_collection.update_one(
                {'username': username},
                {'$set': {'notifications.$[elem].status': 'read'}},
                array_filters=[{'elem.status': 'unread'}]
            )
        
        return jsonify({'notifications': notifications}), 200
        
    except Exception as e:
        print("Error fetching merchant notifications:", str(e))
        return jsonify({'error': 'Failed to fetch notifications'}), 500

@app.route('/market-insights', methods=['GET'])
def get_market_insights():
    try:
        return jsonify({'insights': market_insights}), 200
    except Exception as e:
        print("Error fetching market insights:", str(e))
        return jsonify({'error': 'Failed to fetch market insights'}), 500

# Message endpoints
@app.route('/messages/send', methods=['POST'])
def send_message():
    try:
        data = request.get_json()
        print("Received Data:", data)  # ✅ Debugging

        sender_type = data.get('senderType')
        from_user = data.get('from')
        to_user = data.get('to')

        if not all([sender_type, from_user, to_user]):
            return jsonify({'error': 'Missing required fields'}), 400

        message_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        if sender_type == 'farmer':
            message_text = data.get('message')
            is_rejection = data.get('isRejection', False)

            if not message_text:
                return jsonify({'error': 'Message text is required'}), 400

            print(f"📩 Farmer {from_user} sending message to Merchant {to_user}")

            # Add message to merchant's notifications
            merchants_collection.update_one(
                {'username': to_user},
                {'$push': {'notifications': {
                    'id': message_id,
                    'type': 'crop_inquiry_response',
                    'message': message_text,
                    'timestamp': timestamp,
                    'status': 'rejected' if is_rejection else 'unread'
                }}}
            )

            if is_rejection:
                # Update farmer's notification status
                farmers_collection.update_one(
                    {'phoneNumber': from_user, 'notifications.data.merchantUsername': to_user},
                    {'$set': {'notifications.$.status': 'rejected'}}
                )

        else:
            # Merchant sending crop inquiry
            crop_id = data.get('cropId')
            quantity = data.get('quantity')

            if not all([crop_id, quantity]):
                return jsonify({'error': 'Crop ID and quantity are required'}), 400

            # Get merchant details
            merchant = merchants_collection.find_one({'username': from_user})
            if not merchant:
                return jsonify({'error': 'Merchant not found'}), 404
            print("✅ Merchant Found:", merchant['name'])

            # Get crop details from MongoDB
            crop = crops_collection.find_one({'id': crop_id})
            if not crop:
                return jsonify({'error': 'Invalid crop ID'}), 400
            print("🌾 Crop Found:", crop['englishName'])

            # Ensure notifications field exists before pushing
            farmers_collection.update_one(
                {'phoneNumber': to_user},
                {'$push': {'notifications': {
                    'id': message_id,
                    'type': 'crop_inquiry',
                    'message': f"వ్యాపారి {merchant['name']} {quantity} కిలోల {crop['teluguName']} కొనుగోలు చేయడానికి ఆసక్తి చూపుతున్నారు",
                    'timestamp': timestamp,
                    'status': 'unread',
                    'data': {
                        'merchantUsername': from_user,
                        'cropId': crop_id,
                        'quantity': quantity
                    }
                }}},
                upsert=True
            )

        print("✅ Message Sent Successfully")
        return jsonify({'message': 'Message sent successfully'}), 200

    except Exception as e:
        print("❌ Error sending message:", str(e))
        return jsonify({'error': 'Failed to send message', 'details': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
