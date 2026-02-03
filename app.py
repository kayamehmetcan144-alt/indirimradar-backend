from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text  # SQLAlchemy 2.0 uyumluluğu için
from werkzeug.security import generate_password_hash, check_password_hash # Importlar tepeye taşındı
from datetime import datetime, timedelta
from functools import wraps
import jwt
import os

app = Flask(__name__)

# ==================== CONFIGURATION ====================

# CORS Configuration - Allow specific origins
allowed_origins = os.getenv('ALLOWED_ORIGINS', 'http://localhost:8000').split(',')
CORS(app, origins=allowed_origins)

# Configuration - Use environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
# JWT için ayrı bir key kullanımı daha güvenlidir, yoksa SECRET_KEY kullanılır
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', app.config['SECRET_KEY'])

# Database Configuration - Support both SQLite (dev) and PostgreSQL (production)
database_url = os.getenv('DATABASE_URL', 'sqlite:///indirimradar.db')

# Fix for Railway PostgreSQL URL (postgres:// -> postgresql://)
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

db = SQLAlchemy(app)

# ==================== MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False) # Admin kontrolü eklendi
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # backref isim çakışmalarını önlemek için back_populates kullanımı önerilir ama şimdilik basit tutuyoruz
    favorites = db.relationship('Favorite', backref='user', lazy=True)
    alerts = db.relationship('PriceAlert', backref='user', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(500), nullable=False)
    platform = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    current_price = db.Column(db.Float, nullable=False)
    original_price = db.Column(db.Float, nullable=False)
    discount_percent = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(1000), nullable=False)
    product_url = db.Column(db.String(1000), nullable=False)
    real_deal_status = db.Column(db.String(20), default='normal')  # real, normal, fake
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    price_history = db.relationship('PriceHistory', backref='product', lazy=True)

class PriceHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PriceAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    target_price = db.Column(db.Float, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== AUTH DECORATOR ====================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            token = token.replace('Bearer ', '')
            # JWT_SECRET_KEY kullanımı standartlaştırıldı
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            
            # GÜVENLİK DÜZELTMESİ: Kullanıcı silinmişse kontrol et
            if not current_user:
                return jsonify({'message': 'User invalid or deleted'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
        except Exception as e:
            return jsonify({'message': 'Authentication error', 'error': str(e)}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Basit bir admin decorator örneği (İleride kullanılabilir)
def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'message': 'Admin privileges required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# ==================== AUTH ROUTES ====================

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'User already exists'}), 400
    
    new_user = User(
        email=data['email'],
        password=generate_password_hash(data['password'])
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    token = jwt.encode({
        'user_id': new_user.id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }, app.config['JWT_SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'token': token,
        'user': {
            'id': new_user.id,
            'email': new_user.email,
            'is_premium': new_user.is_premium
        }
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400

    user = User.query.filter_by(email=data['email']).first()
    
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    if not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }, app.config['JWT_SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'email': user.email,
            'is_premium': user.is_premium
        }
    })

# ==================== PRODUCT ROUTES ====================

@app.route('/api/products', methods=['GET'])
def get_products():
    category = request.args.get('category')
    platform = request.args.get('platform')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    query = Product.query
    
    if category and category != 'Tümü':
        query = query.filter_by(category=category)
    
    if platform:
        query = query.filter_by(platform=platform)
    
    # Order by discount percent descending
    query = query.order_by(Product.discount_percent.desc())
    
    products = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'products': [{
            'id': p.id,
            'title': p.title,
            'platform': p.platform,
            'category': p.category,
            'oldPrice': p.original_price,
            'newPrice': p.current_price,
            'discount': p.discount_percent,
            'image': p.image_url,
            'url': p.product_url,
            'realDeal': p.real_deal_status
        } for p in products.items],
        'total': products.total,
        'pages': products.pages,
        'current_page': products.page
    })

@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Get price history
    history = PriceHistory.query.filter_by(product_id=product_id).order_by(PriceHistory.recorded_at.desc()).limit(30).all()
    
    return jsonify({
        'id': product.id,
        'title': product.title,
        'platform': product.platform,
        'category': product.category,
        'oldPrice': product.original_price,
        'newPrice': product.current_price,
        'discount': product.discount_percent,
        'image': product.image_url,
        'url': product.product_url,
        'realDeal': product.real_deal_status,
        'priceHistory': [{
            'price': h.price,
            'date': h.recorded_at.isoformat()
        } for h in history]
    })

# ==================== FAVORITES ROUTES ====================

@app.route('/api/favorites', methods=['GET'])
@token_required
def get_favorites(current_user):
    # Performance Optimization: Join kullanilabilir ama basitlik için şimdilik böyle
    favorites = Favorite.query.filter_by(user_id=current_user.id).all()
    product_ids = [f.product_id for f in favorites]
    
    if not product_ids:
        return jsonify({'favorites': []})

    products = Product.query.filter(Product.id.in_(product_ids)).all()
    
    return jsonify({
        'favorites': [{
            'id': p.id,
            'title': p.title,
            'platform': p.platform,
            'category': p.category,
            'oldPrice': p.original_price,
            'newPrice': p.current_price,
            'discount': p.discount_percent,
            'image': p.image_url,
            'url': p.product_url,
            'realDeal': p.real_deal_status
        } for p in products]
    })

@app.route('/api/favorites', methods=['POST'])
@token_required
def add_favorite(current_user):
    data = request.get_json()
    product_id = data.get('product_id')
    
    if not product_id:
        return jsonify({'message': 'Product ID required'}), 400
    
    # Check if already favorited
    existing = Favorite.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if existing:
        return jsonify({'message': 'Already in favorites'}), 400
    
    favorite = Favorite(user_id=current_user.id, product_id=product_id)
    db.session.add(favorite)
    db.session.commit()
    
    return jsonify({'message': 'Added to favorites'}), 201

@app.route('/api/favorites/<int:product_id>', methods=['DELETE'])
@token_required
def remove_favorite(current_user, product_id):
    favorite = Favorite.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    
    if not favorite:
        return jsonify({'message': 'Not in favorites'}), 404
    
    db.session.delete(favorite)
    db.session.commit()
    
    return jsonify({'message': 'Removed from favorites'})

# ==================== PRICE ALERTS ROUTES ====================

@app.route('/api/alerts', methods=['GET'])
@token_required
def get_alerts(current_user):
    # PERFORMANS DÜZELTMESİ: N+1 Problemi giderildi.
    # Tek sorguda hem alarmı hem de ürün bilgisini çekiyoruz.
    results = db.session.query(PriceAlert, Product).\
        join(Product, PriceAlert.product_id == Product.id).\
        filter(PriceAlert.user_id == current_user.id, PriceAlert.is_active == True).all()
    
    result = []
    for alert, product in results:
        result.append({
            'id': alert.id,
            'target_price': alert.target_price,
            'product': {
                'id': product.id,
                'title': product.title,
                'current_price': product.current_price,
                'image': product.image_url
            }
        })
    
    return jsonify({'alerts': result})

@app.route('/api/alerts', methods=['POST'])
@token_required
def create_alert(current_user):
    data = request.get_json()
    product_id = data.get('product_id')
    target_price = data.get('target_price')

    if not product_id or target_price is None:
        return jsonify({'message': 'Product ID and target price required'}), 400
    
    alert = PriceAlert(
        user_id=current_user.id,
        product_id=product_id,
        target_price=target_price
    )
    
    db.session.add(alert)
    db.session.commit()
    
    return jsonify({'message': 'Price alert created'}), 201

@app.route('/api/alerts/<int:alert_id>', methods=['DELETE'])
@token_required
def delete_alert(current_user, alert_id):
    alert = PriceAlert.query.filter_by(id=alert_id, user_id=current_user.id).first()
    
    if not alert:
        return jsonify({'message': 'Alert not found'}), 404
    
    db.session.delete(alert)
    db.session.commit()
    
    return jsonify({'message': 'Alert deleted'})

# ==================== STATS ROUTES ====================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    total_products = Product.query.count()
    total_deals = Product.query.filter(Product.discount_percent >= 20).count()
    avg_discount = db.session.query(db.func.avg(Product.discount_percent)).scalar()
    
    return jsonify({
        'total_products': total_products,
        'total_deals': total_deals,
        'avg_discount': round(avg_discount, 2) if avg_discount else 0
    })

# ==================== ADMIN ROUTES ====================

# NOT: Prodüksiyon ortamında bu rotalara @admin_required (yukarıda tanımlı) eklenmelidir.
@app.route('/api/admin/products', methods=['POST'])
def admin_create_product():
    data = request.get_json()
    
    product = Product(
        title=data['title'],
        platform=data['platform'],
        category=data['category'],
        current_price=data['current_price'],
        original_price=data['original_price'],
        discount_percent=data['discount_percent'],
        image_url=data['image_url'],
        product_url=data['product_url'],
        real_deal_status=data.get('real_deal_status', 'normal')
    )
    
    db.session.add(product)
    db.session.commit()
    
    # Add to price history
    history = PriceHistory(product_id=product.id, price=data['current_price'])
    db.session.add(history)
    db.session.commit()
    
    return jsonify({'message': 'Product created', 'id': product.id}), 201

@app.route('/api/admin/products/<int:product_id>', methods=['PUT'])
def admin_update_product(product_id):
    product = Product.query.get_or_404(product_id)
    data = request.get_json()
    
    # Update fields
    if 'title' in data:
        product.title = data['title']
    if 'current_price' in data:
        old_price = product.current_price
        product.current_price = data['current_price']
        
        # Add to price history if price changed
        if old_price != data['current_price']:
            history = PriceHistory(product_id=product.id, price=data['current_price'])
            db.session.add(history)
            
            # Check alerts
            alerts = PriceAlert.query.filter_by(product_id=product_id, is_active=True).all()
            for alert in alerts:
                # Fiyat hedef fiyatın altına düştüyse veya eşitse
                if data['current_price'] <= alert.target_price:
                    # In production, send notification here
                    print(f"!!! ALERT TRIGGERED for user {alert.user_id} on product {product.title}")
    
    if 'real_deal_status' in data:
        product.real_deal_status = data['real_deal_status']
    
    product.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'message': 'Product updated'})

@app.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
def admin_delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    
    return jsonify({'message': 'Product deleted'})

# ==================== INITIALIZE DATABASE ====================

def init_db():
    """Initialize database with tables and sample data"""
    with app.app_context():
        db.create_all()
        
        # Add sample data if database is empty
        if Product.query.count() == 0:
            sample_products = [
                {
                    'title': 'iPhone 15 Pro Max 256GB',
                    'platform': 'Trendyol',
                    'category': 'Elektronik',
                    'current_price': 67499,
                    'original_price': 89999,
                    'discount_percent': 25,
                    'image_url': 'https://images.unsplash.com/photo-1696446702001-80b18e0879f9?w=500&q=80',
                    'product_url': 'https://www.trendyol.com',
                    'real_deal_status': 'real'
                },
                {
                    'title': 'Samsung 65" QLED 4K Smart TV',
                    'platform': 'Hepsiburada',
                    'category': 'Elektronik',
                    'current_price': 32999,
                    'original_price': 45999,
                    'discount_percent': 28,
                    'image_url': 'https://images.unsplash.com/photo-1593359677879-a4bb92f829d1?w=500&q=80',
                    'product_url': 'https://www.hepsiburada.com',
                    'real_deal_status': 'real'
                },
                {
                    'title': 'Nike Air Max 270 Erkek Spor Ayakkabı',
                    'platform': 'N11',
                    'category': 'Moda',
                    'current_price': 2999,
                    'original_price': 4999,
                    'discount_percent': 40,
                    'image_url': 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=500&q=80',
                    'product_url': 'https://www.n11.com',
                    'real_deal_status': 'real'
                }
            ]
            
            for data in sample_products:
                product = Product(**data)
                db.session.add(product)
                db.session.commit()
                
                # Add price history
                history = PriceHistory(product_id=product.id, price=data['current_price'])
                db.session.add(history)
            
            db.session.commit()
            print("✅ Sample data added!")

# ==================== HEALTH CHECK ====================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check database connection (SQLAlchemy 2.0 compatible)
        db.session.execute(text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        'message': '🔥 İndirimRadar API',
        'version': '1.0.1', # Versiyon güncellendi
        'status': 'running',
        'endpoints': {
            'health': '/health',
            'products': '/api/products',
            'auth': '/api/auth/login',
            'stats': '/api/stats'
        }
    })

# ==================== RUN ====================

if __name__ == '__main__':
    # Initialize database on first run
    init_db()
    
    # Get port from environment variable
    port = int(os.getenv('PORT', 5000))
    
    # Run app
    is_production = os.getenv('FLASK_ENV') == 'production'
    app.run(
        debug=not is_production,
        host='0.0.0.0',
        port=port
    )
