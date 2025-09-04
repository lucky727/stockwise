# Flask Inventory & Employee Management System

A Flask-based web application for **user authentication, employee management, and inventory management**.  
Supports user sign-up, login, password reset with OTP, and an admin panel to manage products, issues, returns, and transactions.

---

## Features

### User Management
- Sign-up / Login / Logout functionality
- Password hashing with Flask-Bcrypt
- Forgot password with OTP verification via Gmail
- Role-based access (`admin` vs `user`)

### Employee Management
- View all registered employees
- Admin can manage employee details

### Inventory Management System (IMS)
- Add, update, and delete products
- Issue and return products (pcs, boxes, meters)
- Track serial numbers or meter ranges
- View current stock and manage stock as admin
- View transaction history (issued and returned products)

### Technical Features
- MySQL database with SQLAlchemy ORM
- Flask-Migrate for database migrations
- Flask-Mail for sending OTP emails
- Jinja2 templates for dynamic rendering
- Secure session management and cookie handling

---

## Installation

1. **Clone the repository**
```bash
git clone <repository_url>
cd <repository_folder>
```

2. **Create and activate a virtual environment**
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / Mac
source venv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure MySQL database**
Update `app.config['SQLALCHEMY_DATABASE_URI']` in `app.py`:
```python
mysql+pymysql://<username>:<password>@<host>/<database>
```

5. **Initialize database**
```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

6. **Run the application**
```bash
python app.py
```
Open in browser: `http://127.0.0.1:5000`

---

## File Structure

```
project/
│
├── templates/           # HTML templates
│   ├── layout.html
│   ├── index.html
│   ├── signup.html
│   ├── login.html
│   ├── dashboard.html
│   ├── employee.html
│   ├── IMS_dash.html
│   ├── product.html
│   └── ...
│
├── static/              # CSS, JS, images
│
├── app.py               # Main Flask application
├── requirements.txt     # Python dependencies
└── README.md
```

---

## Routes Overview

| Route                     | Method       | Description |
|----------------------------|-------------|-------------|
| `/`                        | GET         | Home page / list of users |
| `/signup`                  | GET, POST   | User registration |
| `/login`                   | GET, POST   | User login |
| `/logout`                  | GET, POST   | Logout and clear session |
| `/dashboard`               | GET         | User dashboard |
| `/forgot_password`         | GET, POST   | Request OTP for password reset |
| `/reset`                   | GET, POST   | Verify OTP |
| `/newpassword`             | GET, POST   | Set new password |
| `/add_product`             | GET, POST   | Add new products (admin only) |
| `/Ims`                     | GET         | IMS dashboard |
| `/issue`                   | GET, POST   | Issue products |
| `/return`                  | GET, POST   | Return products |
| `/view_stock`              | GET, POST   | View all stock |
| `/stock_manager`           | GET, POST   | Admin: manage stock |
| `/update_stock/<int:Pid>` | POST        | Admin: update stock quantity |
| `/delete/<int:id>`         | POST        | Delete a product |
| `/view_issues`             | GET, POST   | View user's issued products |
| `/transactions`            | GET         | View issued/returned transactions |
| `/scan`                    | GET         | Barcode scanning page |
| `/employee`                | GET, POST   | View all employees |

---

## Dependencies
- Flask  
- Flask-SQLAlchemy  
- Flask-Migrate  
- Flask-Bcrypt  
- Flask-Mail  
- Flask-MySQL / PyMySQL  
- SQLAlchemy  

Install via:
```bash
pip install flask flask_sqlalchemy flask_migrate flask_bcrypt flask_mail flaskext.mysql pymysql
```

---

## Notes
- Admin role required to add/update/delete products
- OTP is sent via Gmail; update `MAIL_USERNAME` and `MAIL_PASSWORD` in `app.config`
- Passwords are securely hashed using **bcrypt**

