import os
import uuid
from datetime import datetime
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, IntegerField, DecimalField, FileField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, NumberRange, Email
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import secrets


# Initialize Flask app
app = Flask(__name__)

# Configuration
class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///big_m_auto_spares.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_secret_key')
    UPLOAD_FOLDER = 'static/images'
    CACHE_TYPE = 'simple'  # Use 'redis' or 'memcached' in production
    MAIL_SERVER = 'smtp.gmail.com'  # Use your email provider's SMTP server
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')  # Your email
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')  # Your email password
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_USERNAME')

app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
cache = Cache(app)
mail = Mail(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Set the login route

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Constants
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Models
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    part_number = db.Column(db.String(100), nullable=False)
    make = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    supplier = db.Column(db.String(255), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    image_file = db.Column(db.String(120), nullable=True)

    def __repr__(self):
        return f"<Product {self.name}>"

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(255), nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    date_ordered = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    reset_token = db.Column(db.String(32), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self):
        self.reset_token = secrets.token_hex(16)
        db.session.commit()
        return self.reset_token

# Forms
class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    part_number = StringField('Part Number', validators=[DataRequired()])
    make = StringField('Make', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    price = DecimalField('Price', validators=[DataRequired(), NumberRange(min=0.01)])
    supplier = StringField('Supplier', validators=[DataRequired()])
    image = FileField('Product Image')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')


# User Loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))



@app.route('/products')
@login_required
@cache.cached(timeout=50)
def products():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    all_products = Product.query.paginate(page=page, per_page=per_page)
    return render_template('products.html', products=all_products)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    if not query:
        flash("Please enter a search term.", "warning")
        return redirect(url_for('products'))

    search_results = Product.query.filter(
        (Product.name.ilike(f'%{query}%')) |
        (Product.part_number.ilike(f'%{query}%')) |
        (Product.description.ilike(f'%{query}%'))
    )

    page = request.args.get('page', 1, type=int)
    per_page = 10
    paginated_results = search_results.paginate(page=page, per_page=per_page)

    return render_template('products.html', products=paginated_results)

@app.route('/add-product', methods=['GET', 'POST'])
@login_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        try:
            name = form.name.data
            part_number = form.part_number.data
            make = form.make.data
            description = form.description.data
            quantity = form.quantity.data
            price = form.price.data
            supplier = form.supplier.data

            image_file = form.image.data
            filename = None
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                unique_filename = str(uuid.uuid4()) + "_" + filename
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                filename = unique_filename

            new_product = Product(
                name=name, part_number=part_number, make=make,
                description=description, quantity=quantity,
                price=price, supplier=supplier, image_file=filename
            )
            db.session.add(new_product)
            db.session.commit()
            flash("Product added successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while adding the product.", "danger")
        return redirect(url_for('products'))
    return render_template('add_product.html', form=form)

@app.route('/edit-product/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_product(id):
    product = Product.query.get_or_404(id)
    form = ProductForm(obj=product)
    if form.validate_on_submit():
        try:
            product.name = form.name.data
            product.part_number = form.part_number.data
            product.make = form.make.data
            product.description = form.description.data
            product.quantity = form.quantity.data
            product.price = form.price.data
            product.supplier = form.supplier.data

            image_file = form.image.data
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                unique_filename = str(uuid.uuid4()) + "_" + filename
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                product.image_file = unique_filename

            db.session.commit()
            flash("Product updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while updating the product.", "danger")
        return redirect(url_for('products'))
    return render_template('edit_product.html', form=form, product=product)

@app.route('/delete-product/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    try:
        db.session.delete(product)
        db.session.commit()
        flash("Product deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while deleting the product.", "danger")
    return redirect(url_for('products'))

@app.route('/add-to-cart/<int:product_id>')
@login_required
def add_to_cart(product_id):
    product = db.session.get(Product, product_id)
    if not product:
        flash("Product not found!", "danger")
        return redirect(url_for('products'))

    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']
    product_id_str = str(product_id)

    if product_id_str in cart:
        cart[product_id_str]['quantity'] += 1
    else:
        cart[product_id_str] = {
            'name': product.name,
            'price': float(product.price),
            'quantity': 1
        }

    session['cart'] = cart
    session.modified = True
    flash(f"{product.name} added to cart!", "success")
    return redirect(url_for('view_cart'))

@app.route('/view-cart')
@login_required
def view_cart():
    cart = session.get('cart', {})
    total_price = sum(item['price'] * item['quantity'] for item in cart.values())
    return render_template('cart.html', cart=cart, total_price=total_price)

@app.route('/remove-from-cart/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    product_id_str = str(product_id)

    if product_id_str in cart:
        del cart[product_id_str]
        session['cart'] = cart
        session.modified = True
        flash("Product removed from cart!", "success")
    return redirect(url_for('view_cart'))

@app.route('/clear-cart')
@login_required
def clear_cart():
    session.pop('cart', None)
    flash("Cart cleared successfully!", "info")
    return redirect(url_for('view_cart'))

@app.route('/print-receipt', methods=['GET', 'POST'])
@login_required
def print_receipt():
    if request.method == 'POST':
        customer_name = request.form.get('customer_name', 'Anonymous')
        cart = session.get('cart', {})
        if not cart:
            flash("Your cart is empty!", "warning")
            return redirect(url_for('view_cart'))

        total_price = sum(item['price'] * item['quantity'] for item in cart.values())
        new_order = Order(
            customer_name=customer_name,
            total_price=total_price,
            date_ordered=datetime.utcnow()
        )
        db.session.add(new_order)
        db.session.commit()
        session.pop('cart', None)
        return render_template(
            'receipt.html',
            cart=cart,
            total_price=total_price,
            current_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            customer_name=customer_name
        )
    else:
        return render_template('checkout.html')

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route('/increase-quantity/<int:product_id>', methods=['POST'])
@login_required
def increase_quantity(product_id):
    cart = session.get('cart', {})
    product_id_str = str(product_id)

    if product_id_str in cart:
        cart[product_id_str]['quantity'] += 1
        session['cart'] = cart
        session.modified = True
        flash(f"Quantity increased for {cart[product_id_str]['name']}!", "success")
    return redirect(url_for('view_cart'))

@app.route('/reduce-quantity/<int:product_id>', methods=['POST'])
@login_required
def reduce_quantity(product_id):
    cart = session.get('cart', {})
    product_id_str = str(product_id)

    if product_id_str in cart:
        if cart[product_id_str]['quantity'] > 1:
            cart[product_id_str]['quantity'] -= 1
            session['cart'] = cart
            session.modified = True
            flash(f"Quantity reduced for {cart[product_id_str]['name']}!", "success")
        else:
            del cart[product_id_str]
            session['cart'] = cart
            session.modified = True
            flash(f"{cart[product_id_str]['name']} removed from cart!", "info")
    return redirect(url_for('view_cart'))

# Main Entry Point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)