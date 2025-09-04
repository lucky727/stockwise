from flask import Flask, render_template,request, url_for, redirect, session, flash,jsonify
from flask_sqlalchemy import SQLAlchemy
from flaskext.mysql import MySQL
import pymysql
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import secrets, string
from flask_mail import Mail, Message
from sqlalchemy import text

app = Flask(__name__)
app.secret_key = "supersecretkey"
bcrypt = Bcrypt(app)

# mail configuration
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'luckyvishwakarma758@gmail.com'
app.config['MAIL_PASSWORD'] = 'kqaz epct fets oots'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


#database connection and config

import os

url = "postgresql://stockwise_db_c8l7_user:6YZeinmkXSdcxZ6CXlYPCmG21C0cZI0t@dpg-d2sgt17diees738sb0ng-a.oregon-postgres.render.com/stockwise_db_c8l7"

# if DATABASE_URL comes from environment, fix prefix if needed
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)


#model making / table in db
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100),nullable=False)
    role = db.Column(db.String(50))
    





@app.route('/',)
def index():
    
    users = User.query.all()
    return render_template('index.html',users=users)


@app.route('/signup',methods=['GET', 'POST'])
def signup():
    if request.method=="POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get('password')
        cpassword= request.form.get('cpassword')
        
        if password==cpassword:
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email,password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            return render_template('index.html', username=username,email=email)
        else:
            flash("Passwords do not match!", "error")
            return render_template('signup.html')
    return render_template('signup.html')


@app.route('/login',methods = ['POST','GET'])
def login():
    if request.method=="POST":
        
        email = request.form.get("email")
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['username'] = user.username
            session['email']= user.email
            session['role'] = user.role
            session['user_id'] = user.id

            resp =redirect(url_for('dashboard'))
            resp.set_cookie("username",user.username, max_age=60*1)
            return resp
        else:
            return render_template('login.html', error="Invalid username or email")
        
    return render_template('login.html')



@app.route("/logout",methods =['GET','POST'])
def logout():
    session.pop('username', None)
    resp= redirect(url_for('login'))
    resp.delete_cookie("username")
    return resp


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        return render_template('dashboard.html', user=user)
    return redirect(url_for('login'))




#otp
@app.route("/forgot_password", methods = ['POST','GET'])
def forgot(length = 6):
    
    if request.method=="POST":
        email = request.form.get("email")
        check_email =  User.query.filter_by(email=email).first()
        if check_email:
            digits = string.digits
            otp = ''.join(secrets.choice(digits) for _ in range(length))
            print(otp)
            session['otp'] = otp           # store OTP in session
            session['email'] = email  
            
            msg = Message(subject='Hello', sender = 'luckyvishwakarma758@gmail.com', recipients = [email])
            msg.body = f"This is your OTP: {otp} for resetting your password"
            mail.send(msg)
            return redirect(url_for('verify_otp'))
        else:
            return "no user registered with provided email"
        
    return render_template('forgot.html')
    


@app.route("/reset", methods=['GET', 'POST'])
def verify_otp():
    if request.method == "POST":
        user_otp = request.form.get("otp")
        print(user_otp)
        session_otp = session.get('otp')   # safely get stored OTP

        if not session_otp:
            
            return "⚠️ No OTP found. Please request a new one."
        print(f"{user_otp}----{session_otp}")
        if user_otp == session_otp:
            
            # OTP verified, go to new password page
            return redirect(url_for("newpassword"))
        else:
            return "❌ Invalid OTP. Try again."


    return render_template("reset.html")


@app.route("/newpassword", methods=['GET', 'POST'])
def newpassword():
    if request.method=="POST":
        password = request.form.get('password')
        cpassword= request.form.get('cpassword')
        if password==cpassword:
            hash_pw = bcrypt.generate_password_hash(password).decode('utf-8')
            email = session.get('email')
            if email:
                user = User.query.filter_by(email=email).first()
                if user:
                    user.password = hash_pw
                    db.session.commit()
                    print("✅ Password updated successfully!")
                    return redirect(url_for('login'))
                else:
                    return "❌ User not found."
    return render_template('newpassword.html')





#for ims
class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100),unique=True,nullable= False)
    Category =db.Column(db.String(100),nullable= False)
    qty = db.Column(db.Integer,nullable= False)
    unit = db.Column(db.String(20), nullable=False, default="pcs")  

    # Relationship to Issue
    issues = db.relationship('Issue', backref='product', cascade="all, delete-orphan")


class Issue(db.Model):
    __tablename__ = 'issue'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    product_id = db.Column(db.Integer,db.ForeignKey('product.id'),nullable=False)
    quantity = db.Column(db.Integer)
    unit = db.Column(db.String(50), nullable=False)   # store for historical accuracy
    from_meter = db.Column(db.Float)   # e.g., 12.5 meters
    to_meter = db.Column(db.Float)
    serial_no =  db.Column(db.String(50)) 
    
    
class ReturnProduct(db.Model):
    __tablename__ = 'return_product'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer)
    unit = db.Column(db.String(50), nullable=False)
    from_meter = db.Column(db.Float)
    to_meter = db.Column(db.Float)
    serial_no = db.Column(db.String(50))
    returned_at = db.Column(db.DateTime, default=db.func.current_timestamp())  # optional




@app.route("/add_product", methods=["POST", "GET"])
def add_product():
    # Check role first
    if "role" in session and session["role"] == "admin":
        
        if request.method == "POST":
            names = request.form.getlist("name[]")
            categories = request.form.getlist("category[]")
            quantities = request.form.getlist("quantity[]")
            units = request.form.getlist("unit[]")

            for i in range(len(names)):
                product = Product(
                    Name=names[i],
                    Category=categories[i],
                    unit=units[i],
                    qty=quantities[i]
                )
                db.session.add(product)
            
            db.session.commit()   # commit once
            flash("Products added successfully!")
            return redirect(url_for("dashboard"))

        # If admin but GET request → maybe show form
        return render_template("product.html")

    # If not admin → redirect to login
    flash("Unauthorized! Please login as admin.")
    return redirect(url_for("login"))




@app.route("/Ims")
def IMS():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("IMS_dash.html")



@app.route("/issue", methods=['GET', 'POST'])
def issuestocks():
    if "username" not in session:
        return redirect(url_for("login"))
    
    if request.method == 'POST':
        product_ids = request.form.getlist('product_id[]')
        units = request.form.getlist('unit[]')
        quantities = request.form.getlist('quantity[]')
        barcodes = request.form.getlist('barcode[]')
        meter_froms = request.form.getlist('meter_from[]')
        meter_tos = request.form.getlist('meter_to[]')

        try:
            # Track extra index lists separately (since not every row has barcode/meter inputs)
            barcode_index, meter_index = 0, 0

            for i in range(len(product_ids)):
                if not product_ids[i] or not quantities[i]:
                    continue  # skip empty rows

                pid = int(product_ids[i])
                qty = int(quantities[i])
                unit = units[i]

                # Conditional values
                if unit == "meter":
                    from_meter = meter_froms[meter_index] if meter_index < len(meter_froms) else None
                    to_meter = meter_tos[meter_index] if meter_index < len(meter_tos) else None
                    serial_no = None
                    meter_index += 1
                else:  # pcs/box
                    serial_no = barcodes[barcode_index] if barcode_index < len(barcodes) else None
                    from_meter, to_meter = None, None
                    barcode_index += 1

                # Insert into issue table
                sql_issue = text("""
                    INSERT INTO issue (product_id, quantity, unit, from_meter, to_meter, serial_no, user_id)
                    VALUES (:pid, :qty, :unit, :from_meter, :to_meter, :serial_no, :user_id)
                """)
                db.session.execute(sql_issue, {
                    "pid": pid,
                    "qty": qty,
                    "unit": unit,
                    "from_meter": from_meter if from_meter else None,
                    "to_meter": to_meter if to_meter else None,
                    "serial_no": serial_no if serial_no else None,
                    "user_id": session["user_id"]
                })

                # Update product stock
                sql_update = text("""
                    UPDATE product
                    SET qty = CASE 
                        WHEN qty - :qty < 0 THEN 0
                        ELSE qty - :qty
                    END
                    WHERE id = :pid
                """)
                db.session.execute(sql_update, {"qty": qty, "pid": pid})

            db.session.commit()
            flash("Products issued successfully!", "success")
            return redirect(url_for('issuestocks'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error issuing products: {str(e)}", "error")
            print("ERROR issuing:", e)

    # GET request → show products
    products = db.session.execute(text("SELECT * FROM product")).fetchall()
    return render_template("issue.html", product=products)




#return product logic
@app.route("/return", methods=['GET', 'POST'])
def returnstocks():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == 'POST':
        product_ids = request.form.getlist('product_id[]')
        units = request.form.getlist('unit[]')
        quantities = request.form.getlist('quantity[]')
        barcodes = request.form.getlist('barcode[]')
        meter_froms = request.form.getlist('meter_from[]')
        meter_tos = request.form.getlist('meter_to[]')

        try:
            barcode_index, meter_index = 0, 0

            for i in range(len(product_ids)):
                if not product_ids[i] or not quantities[i]:
                    continue

                pid = int(product_ids[i])
                qty = int(quantities[i])
                unit = units[i]

                # Conditional handling
                if unit == "meter":
                    from_meter = meter_froms[meter_index] if meter_index < len(meter_froms) else None
                    to_meter = meter_tos[meter_index] if meter_index < len(meter_tos) else None
                    serial_no = None
                    meter_index += 1
                else:  # pcs/box
                    serial_no = barcodes[barcode_index] if barcode_index < len(barcodes) else None
                    from_meter, to_meter = None, None
                    barcode_index += 1

                # Insert return
                sql_return = text("""
                    INSERT INTO return_product(product_id, quantity, unit, from_meter, to_meter, serial_no,user_id)
                    VALUES (:pid, :qty, :unit, :from_meter, :to_meter, :serial_no, :user_id)
                """)
                db.session.execute(sql_return, {
                    "pid": pid,
                    "qty": qty,
                    "unit": unit,
                    "from_meter": from_meter if from_meter else None,
                    "to_meter": to_meter if to_meter else None,
                    "serial_no": serial_no if serial_no else None,
                    "user_id": session["user_id"]
                })

                # Update stock (increase qty)
                sql_update = text("""
                    UPDATE product
                    SET qty = qty + :qty
                    WHERE id = :pid
                """)
                db.session.execute(sql_update, {"qty": qty, "pid": pid})

            db.session.commit()
            flash("Products returned successfully!", "success")
            return redirect(url_for('returnstocks'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error returning products: {str(e)}", "error")
            print("ERROR returning:", e)

    # GET request → show products
    products = db.session.execute(text("SELECT * FROM product")).fetchall()
    return render_template("return.html", product=products)





@app.route("/view_stock", methods=['GET', 'POST'])
def stocks():
    if "username" not in session:
        return redirect(url_for("login"))
    
    
    products =Product.query.all()
    
    return render_template("stock.html",items = products)

#for managing - showing , updating and deleting stock.
@app.route("/stock_manager", methods=['GET', 'POST'])
def stock_manager():
    if "username" not in session:
        return redirect(url_for("login"))
    if 'role' in session and session['role'] == 'admin':
        products = Product.query.all()
        return render_template("stock_manager.html", products=products)
    else:
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for("dashboard"))


@app.route("/update_stock/<int:Pid>", methods=['GET', 'POST'])
def update_stock(Pid):
    prod = Product.query.get_or_404(Pid)
    upstock = request.form.get('stock')
    if upstock is not None and upstock.isdigit():
        prod.qty = int(upstock) 
        db.session.commit()
        flash(f"Updated quantity for {prod.Name}", "success")
    return redirect(url_for('stock_manager'))

@app.route("/delete/<int:id>", methods=["POST"])
def delete_product(id):
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    flash(f"{product.Name} deleted successfully!", "danger")
    return redirect(url_for("index"))


@app.route("/view_issues", methods=['GET'])
def view_issues():
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = session.get("user_id")

    # ORM join: returns list of tuples (Issue, Product)
    issues = (
        db.session.query(Issue, Product)
        .join(Product, Issue.product_id == Product.id)
        .filter(Issue.user_id == user_id)
        .all()
    )

    return render_template("view_issues.html", issues=issues)





#transactions

@app.route("/transactions")
def transactions():
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = session.get("user_id")  # current user from session

    # Fetch Issued Transactions
    issued_sql = """
        SELECT 'Issued' AS type, i.id, p."Name" AS product_name, 
               i.quantity, i.unit, i.from_meter, i.to_meter, i.serial_no
        FROM issue i
        JOIN product p ON i.product_id = p.id
        WHERE i.user_id = :user_id
    """

    # Fetch Returned Transactions
    returned_sql = """
        SELECT 'Returned' AS type, r.id, p."Name" AS product_name, 
        r.quantity, r.unit, r.from_meter, r.to_meter, r.serial_no
        FROM return_product r
        JOIN product p ON r.product_id = p.id
        WHERE r.user_id = :user_id
    """

    # Combine both queries with UNION
    sql = f"""
        {issued_sql}
        UNION ALL
        {returned_sql}
        
    """

    transactions = db.session.execute(text(sql), {"user_id": user_id}).mappings().all()

    return render_template("transactions.html", transactions=transactions)



@app.route("/scan")
def scan():
    if 'role' in session and session['role'] == 'admin':
        flash("Welcome admin ji..")
    else:
        flash("Are kaha...?")        
    return render_template("barcode.html")




@app.route('/employee', methods = ('GET','POST'))
def employees():
    employees = User.query.all()
    return render_template("employee.html", employees=employees)


if __name__ == '__main__':
    app.run(host='0.0.0.0',debug = True)
    
with app.app_context():
    db.create_all()
