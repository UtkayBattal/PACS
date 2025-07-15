from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
from datetime import datetime, timedelta, date
import os
import hashlib
from sqlalchemy import create_engine, func, and_, or_, desc, text, cast, String
from sqlalchemy.orm import sessionmaker, scoped_session, joinedload
from zk import ZK
import threading
import time
import re
from io import BytesIO
import xlsxwriter
import pdfkit
from decimal import Decimal
import logging
from flask import make_response
from panel.models import User, Device, Record, Role, Department, Location, Base, DeviceUser, LeaveRequest
import click
from flask.cli import with_appcontext
from zk import ZK, const
from zk.user import User as ZKUser
from zk.finger import Finger
from flask import current_app
# Blueprint modülünü import et
from panel.routes.reports import reports as reports_blueprint
from panel.routes.leave_requests import leave_requests as leave_requests_blueprint

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Sadece konsol handler'ı oluştur
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Blueprint'i kaydet
app.register_blueprint(reports_blueprint)
app.register_blueprint(leave_requests_blueprint)

# Static dosyaların versiyonlanması
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Global değişkenler
device_connections = {}
device_status = {}
sync_intervals = {}
stop_threads = {}
device_privileges = {
    0: "Normal Kullanıcı",
    14: "Yönetici",
    3: "Kayıt"
}

# ZK cihazı için yetki seviyesi dönüşüm haritası
zk_privilege_map = {
    "0": 0,    # Normal Kullanıcı
    "14": 14,  # Yönetici
    "3": 3     # Kayıt
}

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Device manager instance
device_manager = None

# Database bağlantısı
# Çevre değişkenlerini güvenli şekilde al veya varsayılan değerleri kullan
db_user = os.environ.get('DB_USER', 'dbuser')
db_password = os.environ.get('DB_PASSWORD', 'dbpass123')
db_host = os.environ.get('DB_HOST', 'pdks_database')
db_port = os.environ.get('DB_PORT', '5433')  # Port 5433 olarak güncellendi
db_name = os.environ.get('DB_NAME', 'myapp_db')

try:
    DATABASE_URL = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    db_session = scoped_session(SessionLocal)
    logger.info(f"Veritabanı bağlantısı oluşturuldu: {db_host}:{db_port}/{db_name}")
except Exception as e:
    logger.error(f"Veritabanı bağlantısı oluşturulurken hata: {str(e)}")
    raise

# Database session
Session = sessionmaker(bind=engine)

def initialize():
    """Uygulama başlangıç ayarlarını yapar"""
    try:
        # Log dizini yoksa oluştur
        log_dir = os.environ.get('LOG_DIR', '/tmp/pdks_logs')
        os.makedirs(log_dir, exist_ok=True)
        logger.info(f"Log dizini oluşturuldu: {log_dir}")
    except PermissionError:
        logger.warning("Log dizini oluşturulamadı: İzin reddedildi. Geçici dizin kullanılacak.")
    
    # Database bağlantısını kontrol et
    try:
        db_session.execute(text('SELECT 1'))
        logger.info("Veritabanı bağlantısı başarılı.")
    except Exception as e:
        logger.error(f"Veritabanı bağlantı hatası: {str(e)}")

class AuthUser(UserMixin):
    def __init__(self, user):
        self.id = user.user_id
        self.user_id = user.user_id  # Hem id hem user_id için
        self.email = user.email
        self.name = user.name
        self.role_id = user.role_id

    @property
    def is_admin(self):
        return self.role_id == 1

    @property
    def is_authorized(self):
        return self.role_id in [1, 2]
    
    @property
    def is_employee(self):
        return self.role_id == 3
    
    @property
    def is_supervisor(self):
        return self.role_id == 2

def verify_password(stored_password_hex, provided_password):
    """Şifre doğrulama fonksiyonu"""
    logger.info(f"Şifre doğrulama başladı - Stored: {stored_password_hex}, Provided: {provided_password}")
    
    # Eğer stored_password_hex None ise
    if not stored_password_hex:
        logger.warning("Kayıtlı şifre None!")
        return False
        
    # Önce düz metin kontrolü yap
    if stored_password_hex == provided_password:
        logger.info("Düz metin şifre eşleşti!")
        return True
        
    try:
        # Hex'ten bytes'a çevir
        stored_password = bytes.fromhex(stored_password_hex)
        logger.info("Hex'ten bytes'a çevirme başarılı")
        
        # Salt'ı ayır (ilk 32 byte)
        salt = stored_password[:32]
        stored_key = stored_password[32:]
        logger.info("Salt ve key ayrıldı")
        
        # Verilen şifreyi aynı şekilde hashle
        key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000
        )
        logger.info("Verilen şifre hashlendi")
        
        # Karşılaştır
        result = key == stored_key
        logger.info(f"Hash karşılaştırma sonucu: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Şifre doğrulama hatası: {str(e)}")
        # Hata durumunda son bir kez düz metin kontrolü yap
        return stored_password_hex == provided_password

def hash_password(password):
    """Şifreyi hashleyip veritabanına kaydetmek için hazırlar"""
    try:
        # Rastgele salt oluştur
        salt = os.urandom(32)
        
        # Şifreyi hashle
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # 100,000 iterasyon
        )
        
        # Salt ve hash'i birleştir ve hex'e çevir
        return (salt + key).hex()
    except Exception as e:
        logger.error(f"Şifre hashleme hatası: {str(e)}")
        raise

def admin_required(f):
    """Sadece Admin (role_id = 1) kullanıcıları için decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        if current_user.role_id != 1:
            logger.warning(f"Admin yetkisi gerekli - User: {current_user.email}, Role: {current_user.role_id}")
            flash('Yetkisiz Erişim! Bu sayfaya erişim yetkiniz bulunmamaktadır.', 'danger')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

def employee_required(f):
    """Sadece Employee (role_id = 3) kullanıcıları için decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        if current_user.role_id != 3:
            flash('Bu sayfaya erişim yetkiniz bulunmamaktadır!', 'danger')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_or_supervisor_required(f):
    """Admin (role_id = 1) veya Supervisor (role_id = 2) kullanıcıları için decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        if current_user.role_id not in [1, 2]:
            flash('Bu sayfaya erişim yetkiniz bulunmamaktadır!', 'danger')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    try:
        user = db_session.query(User).options(
            joinedload(User.role)
        ).filter_by(user_id=user_id).first()
        
        if user:
            return AuthUser(user)
        return None
    finally:
        db_session.remove()

@app.route('/')
@login_required
@admin_or_supervisor_required
def index():
    logger.info("Index sayfası açılıyor...")
    try:
        # Kullanıcı giriş durumunu kontrol et
        if not current_user.is_authenticated:
            logger.warning("Kullanıcı oturum açmamış, giriş sayfasına yönlendiriliyor")
            return redirect(url_for('login'))
        
        logger.info(f"Giriş yapan kullanıcı: {current_user.email if hasattr(current_user, 'email') else 'Bilinmiyor'}")
        
        # Son 10 kaydı al
        raw_records = db_session.query(Record, User, Device)\
            .join(User, Record.user_id == User.user_id)\
            .outerjoin(Device, Record.device_id == Device.device_id)\
            .filter(Record.deleted_at.is_(None))\
            .order_by(Record.id.desc())\
            .limit(10).all()
        
        # Row objectlerini tuple'a çevir
        records = []
        for record_row in raw_records:
            record = record_row[0] if record_row and len(record_row) > 0 else None
            user = record_row[1] if record_row and len(record_row) > 1 else None
            device = record_row[2] if record_row and len(record_row) > 2 else None
            
            if record and user:  # Sadece geçerli kayıtları ekle
                records.append((record, user, device))
        
        logger.info(f"Kayıt sayısı: {len(records)}")
        
        # Debug için ilk kaydın detaylarını logla
        if records:
            first_record, first_user, first_device = records[0]
            logger.info(f"İlk kayıt - Record ID: {first_record.id if first_record else 'None'}, "
                        f"User: {first_user.name if first_user else 'None'}, "
                        f"Device: {first_device.name if first_device else 'None'}")
        
        # Eğer kayıt yoksa debug bilgisi
        if not records:
            total_records = db_session.query(Record).count()
            logger.warning(f"Ana sayfada kayıt bulunamadı. Toplam kayıt sayısı: {total_records}")
            
            # Silme durumu kontrolü
            deleted_records = db_session.query(Record).filter(Record.deleted_at.is_not(None)).count()
            active_records = db_session.query(Record).filter(Record.deleted_at.is_(None)).count()
            logger.info(f"Silinmemiş kayıt sayısı: {active_records}, Silinmiş kayıt sayısı: {deleted_records}")
            
            # Kullanıcı ve cihaz bilgisi kontrol et
            total_users = db_session.query(User).count()
            total_devices = db_session.query(Device).count()
            logger.info(f"Toplam kullanıcı: {total_users}, Toplam cihaz: {total_devices}")
            
            # Sample record check
            sample_record = db_session.query(Record).first()
            if sample_record:
                logger.info(f"Örnek kayıt - ID: {sample_record.id}, User ID: {sample_record.user_id}, Device ID: {sample_record.device_id}")
        else:
            logger.info(f"Ana sayfada {len(records)} kayıt bulundu")
        
        # Toplam kullanıcı sayısı
        user_count = db_session.query(User)\
            .filter(User.deleted_at.is_(None))\
            .count()
        
        # Bugünkü kayıt sayısı
        today_records = db_session.query(Record)\
            .filter(
                Record.deleted_at.is_(None),
                func.date(Record.timestamp) == datetime.now().date()
            ).count()
            
        # İçerideki personel sayısı
        active_users = db_session.query(func.count(Record.user_id))\
            .filter(
                Record.deleted_at.is_(None),
                Record.punch == 0,  # 0 = Giriş
                func.date(Record.timestamp) == datetime.now().date()
            ).scalar()
            
        # Cihaz istatistikleri
        total_devices = db_session.query(Device)\
            .filter(Device.deleted_at.is_(None))\
            .count()
            
        connected_devices = db_session.query(Device)\
            .filter(
                Device.deleted_at.is_(None),
                Device.last_status == 'connected'
            ).count()
        
        logger.info("Template render ediliyor: index.html")
            
        return render_template('index.html',
                             records=records,
                             user_count=user_count,
                             today_records=today_records,
                             active_users=active_users,
                             total_devices=total_devices,
                             connected_devices=connected_devices)
                             
    except Exception as e:
        logger.error(f"Index sayfası hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return render_template('index.html')
    finally:
        db_session.remove()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        logger.info(f"Login denemesi - Email: {email}")
        
        if not email or not password:
            logger.warning("Email veya şifre boş!")
            flash('Email ve şifre gerekli!', 'danger')
            return redirect(url_for('login'))
            
        try:
            # 1. Email kontrolü
            user = db_session.query(User).filter_by(email=email, deleted_at=None).first()
            
            if not user:
                logger.warning(f"Kullanıcı bulunamadı: {email}")
                flash('Geçersiz email adresi!', 'danger')
                return redirect(url_for('login'))
                
            logger.info(f"Kullanıcı bulundu - ID: {user.user_id}, Role: {user.role_id}")
            
            # 2. Şifre kontrolü
            if not verify_password(user.password, password):
                logger.warning(f"Yanlış şifre - User: {user.email}")
                flash('Yanlış şifre!', 'danger')
                return redirect(url_for('login'))
                
            logger.info(f"Şifre doğrulandı - User: {user.email}")
            
            # 3. Rol kontrolü
            if user.role_id not in [1, 2, 3]:  # Admin (1), Supervisor (2) veya Employee (3) rolü değilse
                logger.warning(f"Yetkisiz erişim - User: {user.email}, Role: {user.role_id}")
                flash('Bu siteye giriş yetkiniz bulunmamaktadır!', 'danger')
                return redirect(url_for('login'))
            
            # 4. Başarılı giriş
            auth_user = AuthUser(user)
            login_user(auth_user)
            logger.info(f"Başarılı giriş - User: {user.email}")
            
            # Flash mesajı ekle
            flash('Başarıyla giriş yaptınız!', 'success')
            
            # Oturum bilgilerini ayarla
            session.permanent = True
            session['logged_in'] = True
            session['user_id'] = user.user_id
            session['user_name'] = user.name
            session['user_email'] = user.email
            session['user_role'] = user.role_id
            
            # Role_id'ye göre yönlendirme
            if user.role_id == 1:  # Admin kullanıcısı - ana sayfaya
                try:
                    target_url = url_for('index')
                    logger.info(f"Admin kullanıcısı ana sayfaya yönlendiriliyor: {target_url}")
                    return redirect(target_url)
                except Exception as redirect_error:
                    logger.error(f"Yönlendirme hatası: {str(redirect_error)}")
                    return redirect('/')
            elif user.role_id == 2:  # Supervisor - ana sayfaya
                try:
                    target_url = url_for('index')
                    logger.info(f"Supervisor kullanıcısı ana sayfaya yönlendiriliyor: {target_url}")
                    return redirect(target_url)
                except Exception as redirect_error:
                    logger.error(f"Yönlendirme hatası: {str(redirect_error)}")
                    return redirect('/')
            elif user.role_id == 3:  # Employee - izin paneline
                logger.info(f"Employee kullanıcısı izin paneline yönlendiriliyor: {user.email}")
                return redirect(url_for('leave_requests.employee_panel'))
            else:
                # Diğer roller için ana sayfa
                return redirect(url_for('index'))
                    
        except Exception as e:
            logger.error(f"Login hatası: {str(e)}")
            flash('Giriş yapılırken bir hata oluştu!', 'danger')
            return redirect(url_for('login'))
        finally:
            db_session.remove()
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    try:
        logger.info(f"Logout başladı - Kullanıcı: {current_user.email if hasattr(current_user, 'email') else 'Bilinmiyor'}")
        
        # Kullanıcı oturumunu sonlandır
        logout_user()
        logger.info("Flask-Login oturumu sonlandırıldı")
        
        # Session'ı tamamen temizle
        session.clear()
        logger.info("Session temizlendi")
        
        # Database session'ı da temizle
        try:
            db_session.remove()
            logger.info("Database session temizlendi")
        except Exception as db_error:
            logger.error(f"Database session temizleme hatası: {str(db_error)}")
        
        # Flash mesajı ekle
        flash('Başarıyla çıkış yaptınız.', 'success')
        
        # Login sayfasına yönlendir
        response = make_response(redirect(url_for('login')))
        
        # Cache kontrolü ekle
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        logger.info("Logout başarılı - Login sayfasına yönlendiriliyor")
        return response
        
    except Exception as e:
        logger.error(f"Logout hatası: {str(e)}")
        # Hata durumunda bile login sayfasına yönlendir
        try:
            session.clear()
            db_session.remove()
        except:
            pass
        flash('Çıkış yapılırken bir hata oluştu, tekrar giriş yapın.', 'warning')
        return redirect(url_for('login'))

@app.route('/users')
@login_required
@admin_or_supervisor_required
def users():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        query = db_session.query(User)\
            .filter(
                User.deleted_at.is_(None),
                User.user_id.is_not(None)
            )\
            .order_by(User.user_id.asc())  # ID'ye göre artan sıralama
            
        total = query.count()
        users_data = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Debug: Kullanıcı verilerini kontrol et
        for user in users_data:
            logger.info(f"User: {user.name}, ID: {user.user_id}, Type: {type(user.user_id)}")
        
        # Departmanları al
        departments = db_session.query(Department)\
            .filter(Department.deleted_at.is_(None))\
            .order_by(Department.department_name)\
            .all()
            
        return render_template(
            'users.html',
            users=users_data,
            departments=departments,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page
        )
    except Exception as e:
        logger.error(f"Kullanıcılar sayfası hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return redirect(url_for('index'))
    finally:
        db_session.remove()

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_or_supervisor_required
def edit_user(user_id):
    """Kullanıcı düzenleme sayfası"""
    try:
        # Kullanıcıyı bul
        user = db_session.query(User).filter(
            User.user_id == user_id,
            User.deleted_at.is_(None)
        ).first()
        
        if not user:
            flash('Kullanıcı bulunamadı!', 'danger')
            return redirect(url_for('users'))
        
        if request.method == 'POST':
            # Form verilerini al
            user.name = request.form.get('name', '').strip()
            user.card_no = request.form.get('card', '').strip()
            tckn = request.form.get('tckn', '').strip()
            user.gender = request.form.get('gender', '').strip()
            user.nationality = request.form.get('nationality', '').strip()
            user.education_level = request.form.get('education_level', '').strip()
            user.occupation = request.form.get('occupation', '').strip()
            user.job_title = request.form.get('job_title', '').strip()
            user.work_type = request.form.get('work_type', '').strip()
            user.employment_status = request.form.get('employment_status', '').strip()
            user.group_id = request.form.get('group_id', None, type=int) if request.form.get('group_id') else None
            user.device_role = request.form.get('device_role', 0, type=int)
            phone_number = request.form.get('phone_number', '').strip()
            start_date = request.form.get('start_date', '').strip()
            end_date = request.form.get('end_date', '').strip()
            
            # TC Kimlik No kontrolü ve güncelleme
            if tckn:
                if not tckn.isdigit() or len(tckn) != 11:
                    flash('TC Kimlik No 11 haneli sayı olmalıdır!', 'warning')
                    return redirect(url_for('edit_user', user_id=user_id))
                user.TCKN = tckn
            
            # Telefon numarası işleme
            if phone_number:
                if not phone_number.isdigit() or len(phone_number) != 10:
                    flash('Telefon numarası 10 haneli sayı olmalıdır!', 'warning')
                    return redirect(url_for('edit_user', user_id=user_id))
                user.phone_number = f"+90{phone_number}"  # Tam numara (+905XXXXXXXXX)
                user.phone_no_country_code = phone_number  # Sadece numara (5XXXXXXXXX)
            # Eğer telefon numarası boşsa mevcut değeri koru (silme)
            
            # Tarih dönüşümleri
            if start_date:
                try:
                    user.start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                except ValueError:
                    flash('Geçersiz başlangıç tarihi formatı!', 'warning')
                    return redirect(url_for('edit_user', user_id=user_id))
            else:
                user.start_date = None
                
            if end_date:
                try:
                    user.end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                except ValueError:
                    flash('Geçersiz bitiş tarihi formatı!', 'warning')
                    return redirect(url_for('edit_user', user_id=user_id))
            else:
                user.end_date = None
                
            # Tarih mantık kontrolü
            if user.start_date and user.end_date and user.start_date > user.end_date:
                flash('Başlangıç tarihi bitiş tarihinden sonra olamaz!', 'warning')
                return redirect(url_for('edit_user', user_id=user_id))
            
            # Form verilerini güncelle
            user.name = request.form.get('name', '').strip()
            user.email = request.form.get('email', '').strip()
            user.gender = request.form.get('gender', '').strip()
            user.nationality = request.form.get('nationality', '').strip()
            user.education_level = request.form.get('education_level', '').strip()
            user.occupation = request.form.get('occupation', '').strip()
            user.job_title = request.form.get('job_title', '').strip()
            user.work_type = request.form.get('work_type', '').strip()
            user.employment_status = request.form.get('employment_status', '').strip()
            user.group_id = request.form.get('group_id', None, type=int) if request.form.get('group_id') else None
            user.device_role = request.form.get('device_role', 0, type=int)
            
            # Departman işlemi - string olarak gelen departman adını ID'ye çevir
            department_name = request.form.get('department', '').strip()
            if department_name:
                department = db_session.query(Department).filter(
                    Department.department_name == department_name,
                    Department.deleted_at.is_(None)
                ).first()
                
                if department:
                    user.department_id = department.department_id
                else:
                    # Departman yoksa oluştur
                    new_department = Department(department_name=department_name)
                    db_session.add(new_department)
                    db_session.flush()
                    user.department_id = new_department.department_id
            
            # Rol güncellemesi
            role_id = request.form.get('role_id', type=int)
            if role_id:
                role = db_session.query(Role).filter(
                    Role.role_id == role_id,
                    Role.deleted_at.is_(None)
                ).first()
                
                if role:
                    user.role_id = role_id
                    logger.info(f"Kullanıcı {user.name} için rol güncellendi: {role.name}")
            
            # Email güncellemesi
            email = request.form.get('email', '').strip()
            if email and email != user.email:
                # Email benzersizlik kontrolü
                existing_user = db_session.query(User).filter(
                    User.email == email,
                    User.user_id != user_id,
                    User.deleted_at.is_(None)
                ).first()
                
                if existing_user:
                    flash('Bu email adresi başka bir kullanıcı tarafından kullanılıyor!', 'danger')
                    return redirect(url_for('edit_user', user_id=user_id))
                
                user.email = email
            
            # Şifre güncellemesi (isteğe bağlı)
            new_password = request.form.get('password', '').strip()
            if new_password:
                # Şifre uzunluk kontrolü
                if len(new_password) < 4 or len(new_password) > 8:
                    flash('Şifre 4-8 karakter uzunluğunda olmalıdır!', 'warning')
                    return redirect(url_for('edit_user', user_id=user_id))
                    
                user.password = hash_password(new_password)
                user.raw_password = new_password  # Ham şifreyi de kaydet
                logger.info(f"Kullanıcı {user.name} için şifre güncellendi")
            
            # Güncelleme tarihini set et
            user.updated_at = datetime.now()
            
            try:
                db_session.commit()
                flash('Kullanıcı başarıyla güncellendi!', 'success')
                return redirect(url_for('users'))
            except Exception as e:
                db_session.rollback()
                logger.error(f"Kullanıcı güncelleme hatası: {str(e)}")
                flash(f'Kullanıcı güncellenirken hata oluştu: {str(e)}', 'danger')
                return redirect(url_for('edit_user', user_id=user_id))
        
        # GET isteği için departmanları ve rolleri al
        departments = db_session.query(Department)\
            .filter(Department.deleted_at.is_(None))\
            .order_by(Department.department_name)\
            .all()
            
        roles = db_session.query(Role)\
            .filter(Role.deleted_at.is_(None))\
            .order_by(Role.role_id)\
            .all()
        
        return render_template('edit_user.html', user=user, departments=departments, roles=roles)
        
    except Exception as e:
        logger.error(f"Kullanıcı düzenleme sayfası hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return redirect(url_for('users'))
    finally:
        db_session.remove()

def get_next_available_user_id():
    """Mevcut olmayan en düşük user_id değerini bulur"""
    try:
        # Mevcut kullanıcı ID'lerini al (silinmemiş olanları)
        existing_ids = db_session.query(User.user_id)\
            .filter(User.deleted_at.is_(None))\
            .order_by(User.user_id.asc())\
            .all()
        
        existing_ids = [id[0] for id in existing_ids if id[0] is not None]
        
        # Eğer hiç kullanıcı yoksa 1'den başla
        if not existing_ids:
            return 1
            
        # 1'den başlayarak ilk boş ID'yi bul
        next_id = 1
        for current_id in existing_ids:
            if next_id < current_id:
                # Boşluk bulundu
                return next_id
            next_id = current_id + 1
            
        # Hiç boşluk yoksa sonraki sıradaki ID'yi döndür
        return next_id
        
    except Exception as e:
        logger.error(f"User ID bulma hatası: {str(e)}")
        # Hata durumunda timestamp tabanlı ID oluştur
        import time
        return int(time.time()) % 100000

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@admin_or_supervisor_required
def add_user():
    """Kullanıcı ekleme sayfası"""
    try:
        if request.method == 'POST':
            # Zorunlu alanları al
            name = request.form.get('name')
            tckn = request.form.get('tckn')
            gender = request.form.get('gender')
            nationality = request.form.get('nationality')
            education_level = request.form.get('education_level')
            occupation = request.form.get('occupation')
            department_name = request.form.get('department')
            work_type = request.form.get('work_type')
            employment_status = request.form.get('employment_status')
            privilege = request.form.get('privilege')
            password = request.form.get('password')
            selected_role_id = request.form.get('role_id', 3, type=int)  # Varsayılan User rolü
            
            # İsteğe bağlı alanlar
            job_title = request.form.get('job_title', '')
            card_no = request.form.get('card', '')
            group_id = request.form.get('group_id', None)
            phone_number = request.form.get('phone_number', '').strip()
            start_date = request.form.get('start_date', '').strip()
            end_date = request.form.get('end_date', '').strip()
            
            # Email oluştur (ad.soyad formatında)
            email = f"{name.lower().replace(' ', '.')}@belediye.com"
            
            # Zorunlu alanları kontrol et
            required_fields = {
                'Ad Soyad': name,
                'TC Kimlik No': tckn,
                'Cinsiyet': gender,
                'Uyruk': nationality,
                'Eğitim Durumu': education_level,
                'Meslek': occupation,
                'Departman': department_name,
                'Çalışma Tipi': work_type,
                'Çalışma Durumu': employment_status,
                'Yetki Seviyesi': privilege,
                'Sistem Rolü': selected_role_id if selected_role_id != 0 else None,
                'Şifre': password
            }
            
            # Eksik zorunlu alanları kontrol et
            missing_fields = [field for field, value in required_fields.items() if not value]
            if missing_fields:
                flash(f'Lütfen şu zorunlu alanları doldurun: {", ".join(missing_fields)}', 'warning')
                return redirect(url_for('add_user'))
            
            # TC Kimlik No kontrolü
            if not tckn.isdigit() or len(tckn) != 11:
                flash('TC Kimlik No 11 haneli sayı olmalıdır!', 'warning')
                return redirect(url_for('add_user'))
            
            # Şifre kontrolü
            if len(password) < 4 or len(password) > 8:
                flash('Şifre 4-8 karakter uzunluğunda olmalıdır!', 'warning')
                return redirect(url_for('add_user'))
            
            # Telefon numarası işleme
            phone_number_full = None
            phone_number_only = None
            if phone_number:
                if not phone_number.isdigit() or len(phone_number) != 10:
                    flash('Telefon numarası 10 haneli sayı olmalıdır!', 'warning')
                    return redirect(url_for('add_user'))
                phone_number_full = f"+90{phone_number}"  # Tam numara (+905XXXXXXXXX)
                phone_number_only = phone_number  # Sadece numara (5XXXXXXXXX)
            
            # Tarih dönüşümleri
            start_date_obj = None
            end_date_obj = None
            if start_date:
                try:
                    start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
                except ValueError:
                    flash('Geçersiz başlangıç tarihi formatı!', 'warning')
                    return redirect(url_for('add_user'))
                    
            if end_date:
                try:
                    end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
                except ValueError:
                    flash('Geçersiz bitiş tarihi formatı!', 'warning')
                    return redirect(url_for('add_user'))
                    
            # Tarih mantık kontrolü
            if start_date_obj and end_date_obj and start_date_obj > end_date_obj:
                flash('Başlangıç tarihi bitiş tarihinden sonra olamaz!', 'warning')
                return redirect(url_for('add_user'))
            
            try:
                # Mevcut olmayan en düşük user_id'yi al
                new_user_id = get_next_available_user_id()
                logger.info(f"Yeni kullanıcı için atanan ID: {new_user_id}")
                
                # Seçilen rolün varlığını kontrol et
                role = db_session.query(Role).filter(
                    Role.role_id == selected_role_id,
                    Role.deleted_at.is_(None)
                ).first()
                
                if not role:
                    flash('Geçersiz rol seçimi!', 'danger')
                    return redirect(url_for('add_user'))
                
                logger.info(f"Seçilen rol: {role.name} (ID: {selected_role_id})")
                
                # Departmanı bul
                department = db_session.query(Department).filter(
                    Department.department_name == department_name,
                    Department.deleted_at.is_(None)
                ).first()
                
                if not department:
                    # Departman yoksa oluştur
                    department = Department(department_name=department_name)
                    db_session.add(department)
                    db_session.flush()
                
                # Şifreyi hashle
                hashed_password = hash_password(password)
                
                # Yeni kullanıcı oluştur - user_id'yi manuel olarak ata
                new_user = User(
                    user_id=new_user_id,  # Manuel ID atama
                    name=name,
                    email=email,
                    password=hashed_password,
                    raw_password=password,  # Ham şifre
                    gender=gender,
                    nationality=nationality,
                    education_level=education_level,
                    occupation=occupation,
                    job_title=job_title if job_title else None,
                    department_id=department.department_id,
                    card_no=card_no if card_no else None,
                    work_type=work_type,
                    employment_status=employment_status,
                    group_id=int(group_id) if group_id and group_id.isdigit() else None,
                    device_role=int(privilege),
                    role_id=selected_role_id,  # Form'dan gelen rol ID'si
                    status=1,  # Aktif
                    TCKN=tckn,
                    phone_number=phone_number_full,
                    phone_no_country_code=phone_number_only,
                    start_date=start_date_obj,
                    end_date=end_date_obj
                )
                
                db_session.add(new_user)
                db_session.commit()
                
                flash(f'Kullanıcı başarıyla eklendi! (ID: {new_user_id}, Rol: {role.name})', 'success')
                return redirect(url_for('users'))
                
            except Exception as e:
                db_session.rollback()
                logger.error(f"Kullanıcı ekleme hatası: {str(e)}")
                flash(f'Kullanıcı eklenirken bir hata oluştu: {str(e)}', 'danger')
                return redirect(url_for('add_user'))

        # GET isteği için departmanları ve rolleri al
        departments = db_session.query(Department)\
            .filter(Department.deleted_at.is_(None))\
            .order_by(Department.department_name)\
            .all()
            
        roles = db_session.query(Role)\
            .filter(Role.deleted_at.is_(None))\
            .order_by(Role.role_id)\
            .all()
            
        return render_template('add_user.html', departments=departments, roles=roles)
    except Exception as e:
        logger.error(f"Kullanıcı ekleme sayfası hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return redirect(url_for('users'))
    finally:
        db_session.remove()

@app.route('/api/users/add', methods=['POST'])
@login_required
@admin_or_supervisor_required
def create_user():
    try:
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        department_id = request.form.get('department_id')
        
        if not all([name, email, password]):
            flash('Tüm zorunlu alanları doldurun!', 'warning')
            return redirect(url_for('users'))
        
        # Otomatik user_id ata
        new_user_id = get_next_available_user_id()
        logger.info(f"API üzerinden yeni kullanıcı için atanan ID: {new_user_id}")
            
        # Email kontrolü
        existing_user = db_session.query(User)\
            .filter(
                User.email == email,
                User.deleted_at.is_(None)
            ).first()
            
        if existing_user:
            flash('Bu email adresi zaten kullanılıyor!', 'warning')
            return redirect(url_for('users'))
            
        # Şifreyi hashle
        hashed_password = hash_password(password)
        
        new_user = User(
            user_id=new_user_id,  # Otomatik atanan ID
            name=name,
            email=email,
            password=hashed_password,
            department_id=department_id if department_id else None,
            device_role=0,  # Normal kullanıcı
            status=1  # Aktif
        )
        
        db_session.add(new_user)
        db_session.commit()
        
        flash(f'Kullanıcı başarıyla eklendi! (ID: {new_user_id})', 'success')
        return redirect(url_for('users'))
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"Kullanıcı ekleme hatası: {str(e)}")
        flash(f'Kullanıcı eklenirken bir hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('users'))
    finally:
        db_session.remove()

@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@admin_or_supervisor_required
def manage_user(user_id):
    try:
        user = db_session.query(User)\
            .filter(
                User.user_id == user_id,
                User.deleted_at.is_(None)
            ).first()
            
        if not user:
            if request.method == 'GET':
                flash('Kullanıcı bulunamadı!', 'warning')
                return redirect(url_for('users'))
            return jsonify({'success': False, 'message': 'Kullanıcı bulunamadı!'}), 404
            
        if request.method == 'GET':
            # Kullanıcı detayları sayfası
            departments = db_session.query(Department)\
                .filter(Department.deleted_at.is_(None))\
                .all()
                
            return render_template(
                'user_detail.html',
                user=user,
                departments=departments
            )
            
        elif request.method == 'PUT':
            data = request.get_json()
            user.name = data.get('name', user.name)
            user.email = data.get('email', user.email)
            user.department_id = data.get('department_id', user.department_id)
            user.status = data.get('status', user.status)
            
            # Şifre değişimi varsa
            if data.get('password'):
                hashed_password = hash_password(data['password'])
                user.password = hashed_password
                
            db_session.commit()
            return jsonify({'success': True, 'message': 'Kullanıcı güncellendi!'})
            
        elif request.method == 'DELETE':
            user.deleted_at = datetime.now()
            db_session.commit()
            return jsonify({'success': True, 'message': 'Kullanıcı silindi!'})
            
    except Exception as e:
        db_session.rollback()
        logger.error(f"Kullanıcı yönetimi hatası: {str(e)}")
        
        if request.method == 'GET':
            flash(f'Bir hata oluştu: {str(e)}', 'danger')
            return redirect(url_for('users'))
            
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db_session.remove()

# URL versiyonlama için helper fonksiyon
def dated_url_for(endpoint, **values):
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            file_path = os.path.join(app.root_path, endpoint, filename)
            try:
                values['v'] = int(os.stat(file_path).st_mtime)
            except OSError:
                pass
    return url_for(endpoint, **values)

@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)

# Kullanıcı arama sayfası
@app.route('/search_users')
@login_required
@admin_or_supervisor_required
def search_users():
    try:
        search_term = request.args.get('q', '')
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        query = db_session.query(User)\
            .filter(
                User.deleted_at.is_(None),
                User.user_id.is_not(None),
                or_(
                    User.name.ilike(f'%{search_term}%'),
                    User.email.ilike(f'%{search_term}%'),
                    User.card_no.ilike(f'%{search_term}%'),
                    cast(User.user_id, String).ilike(f'%{search_term}%')
                )
            )\
            .order_by(User.user_id.asc())  # ID'ye göre artan sıralama
            
        total = query.count()
        users_data = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Departmanları al
        departments = db_session.query(Department)\
            .filter(Department.deleted_at.is_(None))\
            .order_by(Department.department_name)\
            .all()
            
        return render_template(
            'users.html',
            users=users_data,
            departments=departments,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
            search_term=search_term,
            search=search_term
        )
    except Exception as e:
        logger.error(f"Kullanıcı arama hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return redirect(url_for('users'))
    finally:
        db_session.remove()

# API endpointleri - Kullanıcı listeleme ve arama
@app.route('/api/users/search')
@login_required
@admin_or_supervisor_required
def api_search_users():
    try:
        search_term = request.args.get('q', '')
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        query = db_session.query(User)\
            .filter(
                User.deleted_at.is_(None),
                User.user_id.is_not(None),
                or_(
                    User.name.ilike(f'%{search_term}%'),
                    User.email.ilike(f'%{search_term}%'),
                    User.card_no.ilike(f'%{search_term}%'),
                    cast(User.user_id, String).ilike(f'%{search_term}%')
                )
            )\
            .order_by(User.user_id.asc())  # ID'ye göre artan sıralama
            
        total = query.count()
        users_data = query.offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'success': True,
            'users': [{
                'user_id': user.user_id,
                'name': user.name,
                'email': user.email,
                'department': user.department.department_name if user.department else None,
                'status': user.status
            } for user in users_data],
            'total': total,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        logger.error(f"Kullanıcı arama API hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()

@app.route('/devices')
@login_required
@admin_required
def devices():
    try:
        devices = db_session.query(Device)\
            .filter(Device.deleted_at.is_(None))\
            .order_by(Device.device_id).all()
        
        total_devices = len(devices)
        connected_devices = sum(1 for device in devices if device.last_status == 'connected')
        
        return render_template(
            'devices.html',
            devices=devices,
            total_devices=total_devices,
            connected_devices=connected_devices
        )
    except Exception as e:
        logger.error(f"Cihazlar sayfası hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return redirect(url_for('index'))
    finally:
        db_session.remove()

@app.route('/api/device-status')
@login_required
@admin_required
def device_status_api():
    try:
        devices = db_session.query(Device)\
            .filter(Device.deleted_at.is_(None))\
            .all()
        
        total_devices = len(devices)
        connected_devices = 0
        
        for device in devices:
            if device.is_active and device.last_status == 'connected':
                connected_devices += 1
        
        return jsonify({
            'success': True,
            'total_devices': total_devices,
            'connected_devices': connected_devices,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        })
    except Exception as e:
        logger.error(f"Cihaz durumu API hatası: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    finally:
        db_session.remove()

@app.route('/api/devices/<int:device_id>/connect')
@login_required
@admin_required
def connect_device(device_id):
    try:
        device = db_session.query(Device)\
            .filter(
                Device.device_id == device_id,
                Device.deleted_at.is_(None)
            ).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Cihaz bulunamadı!'})
        
        # Cihaz bağlantısını yap
        zk = ZK(device.ip, port=device.port, timeout=device.timeout)
        conn = zk.connect()
        
        if conn:
            device.last_status = 'connected'
            device.last_connection = datetime.now()
            db_session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Cihaz bağlantısı başarılı!'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Cihaza bağlanılamadı!'
            })
            
    except Exception as e:
        logger.error(f"Cihaz bağlantı hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()

@app.route('/records')
@login_required
@admin_or_supervisor_required
def records():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 30
        
        query = db_session.query(Record, User, Device)\
            .join(User, Record.user_id == User.user_id)\
            .outerjoin(Device, Record.device_id == Device.device_id)\
            .filter(Record.deleted_at.is_(None))\
            .order_by(Record.id.desc())
        
        total = query.count()
        raw_records = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Row objectlerini tuple'a çevir
        records = []
        for row in raw_records:
            if hasattr(row, '_mapping') or hasattr(row, '__getitem__'):
                try:
                    record_obj = row[0] if len(row) > 0 else None
                    user_obj = row[1] if len(row) > 1 else None
                    device_obj = row[2] if len(row) > 2 else None
                    records.append((record_obj, user_obj, device_obj))
                except (IndexError, TypeError):
                    records.append(row)
            else:
                records.append(row)
        
        # Debug için ilk kaydın türünü kontrol et
        if records:
            first_item = records[0]
            logger.info(f"Records tuple türü: {type(first_item)}")
            logger.info(f"Records tuple uzunluk: {len(first_item)}")
            logger.info(f"İlk eleman türü: {type(first_item[0])}")
            logger.info(f"İkinci eleman türü: {type(first_item[1])}")
            logger.info(f"Üçüncü eleman türü: {type(first_item[2])}")
        
        return render_template(
            'records.html',
            records=records,
            page=page,
            per_page=per_page,
            total_records=total,
            total_pages=(total + per_page - 1) // per_page,
            is_search=False,
            search_term='',
            date_from='',
            date_to=''
        )
    except Exception as e:
        logger.error(f"Kayıtlar sayfası hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return redirect(url_for('index'))
    finally:
        db_session.remove()

@app.route('/search_records')
@login_required
@admin_or_supervisor_required
def search_records():
    try:
        search_term = request.args.get('q', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = 30
        
        query = db_session.query(Record, User, Device)\
            .join(User, Record.user_id == User.user_id)\
            .outerjoin(Device, Record.device_id == Device.device_id)\
            .filter(Record.deleted_at.is_(None))
        
        # Arama filtreleri
        if search_term:
            query = query.filter(
                or_(
                    User.name.ilike(f'%{search_term}%'),
                    cast(User.user_id, String).ilike(f'%{search_term}%'),
                    User.card_no.ilike(f'%{search_term}%')
                )
            )
        
        # Tarih filtreleri
        if date_from:
            try:
                from_date = datetime.strptime(date_from, '%Y-%m-%d').date()
                query = query.filter(func.date(Record.timestamp) >= from_date)
            except ValueError:
                pass
                
        if date_to:
            try:
                to_date = datetime.strptime(date_to, '%Y-%m-%d').date()
                query = query.filter(func.date(Record.timestamp) <= to_date)
            except ValueError:
                pass
        
        query = query.order_by(Record.id.desc())
        
        total = query.count()
        raw_records = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Row objectlerini tuple'a çevir
        records = []
        for row in raw_records:
            if hasattr(row, '_mapping') or hasattr(row, '__getitem__'):
                try:
                    record_obj = row[0] if len(row) > 0 else None
                    user_obj = row[1] if len(row) > 1 else None
                    device_obj = row[2] if len(row) > 2 else None
                    records.append((record_obj, user_obj, device_obj))
                except (IndexError, TypeError):
                    records.append(row)
            else:
                records.append(row)
        
        # Debug için ilk kaydın türünü kontrol et (search için)
        if records:
            first_item = records[0]
            logger.info(f"Search Records tuple türü: {type(first_item)}")
        
        return render_template(
            'records.html',
            records=records,
            page=page,
            per_page=per_page,
            total_records=total,
            total_pages=(total + per_page - 1) // per_page,
            is_search=True,
            search_term=search_term,
            date_from=date_from,
            date_to=date_to
        )
        
    except Exception as e:
        logger.error(f"Kayıt arama hatası: {str(e)}")
        flash('Arama sırasında bir hata oluştu!', 'danger')
        return redirect(url_for('records'))
    finally:
        db_session.remove()

@app.route('/reports')
@login_required
@admin_required
def reports_page():
    """Raporlar sayfası"""
    try:
        departments = db_session.query(Department).filter(
            Department.deleted_at.is_(None)
        ).all()
        
        # Çalışanları al
        employees = db_session.query(User).filter(
            User.deleted_at.is_(None)
        ).order_by(User.name).all()
        
        return render_template('reports/reports.html', departments=departments, employees=employees)
    except Exception as e:
        logger.error(f"Raporlar sayfası hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return render_template('reports/reports.html')

@app.route('/fingerprints')
@login_required
@admin_required
def fingerprints():
    """Parmak izi yönetimi sayfası"""
    if not current_user.is_admin:
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    try:
        # Kullanıcıları al
        users = db_session.query(User).filter(
            User.deleted_at.is_(None)
        ).order_by(User.name).all()
        
        # Cihazları al
        devices = db_session.query(Device).filter(
            Device.deleted_at.is_(None),
            Device.is_active == True
        ).all()
        
        return render_template('fingerprints.html',
                             users=users,
                             devices=devices)
    except Exception as e:
        logger.error(f"Parmak izi sayfası hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return render_template('fingerprints.html')

@app.route('/api/fingerprint/enroll', methods=['POST'])
@login_required
@admin_required
def enroll_fingerprint():
    """Parmak izi kaydetme"""
    if not current_user.is_admin:
        return jsonify({
            'success': False,
            'message': 'Bu işlem için yetkiniz yok!'
        }), 403
    
    user_id = request.form.get('user_id')
    device_id = request.form.get('device_id')
    
    if not all([user_id, device_id]):
        return jsonify({
            'success': False,
            'message': 'Eksik parametreler!'
        }), 400
    
    try:
        # Kullanıcıyı kontrol et
        user = db_session.query(User).filter(
            User.user_id == user_id,
            User.deleted_at.is_(None)
        ).first()
        
        if not user:
            return jsonify({
                'success': False,
                'message': 'Kullanıcı bulunamadı!'
            }), 404
        
        # Cihazı kontrol et
        device = db_session.query(Device).filter(
            Device.device_id == device_id,
            Device.deleted_at.is_(None),
            Device.is_active == True
        ).first()
        
        if not device:
            return jsonify({
                'success': False,
                'message': 'Cihaz bulunamadı!'
            }), 404
        
        # Cihaza bağlan
        device_manager = DeviceManager()
        conn = device_manager.get_connection(device.ip, device.port)
        
        if not conn:
            return jsonify({
                'success': False,
                'message': 'Cihaza bağlanılamadı!'
            }), 500
        
        try:
            # Parmak izi kaydını başlat
            conn.enroll_user(user_id)
            
            return jsonify({
                'success': True,
                'message': 'Parmak izi kayıt işlemi başlatıldı. Lütfen parmağınızı cihaza yerleştirin.'
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Parmak izi kaydedilirken bir hata oluştu: {str(e)}'
            }), 500
            
        finally:
            conn.disconnect()
            
    except Exception as e:
        logger.error(f"Parmak izi kaydetme hatası: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/fingerprint/delete', methods=['POST'])
@login_required
@admin_required
def delete_fingerprint():
    """Parmak izi silme"""
    if not current_user.is_admin:
        return jsonify({
            'success': False,
            'message': 'Bu işlem için yetkiniz yok!'
        }), 403
    
    user_id = request.form.get('user_id')
    device_id = request.form.get('device_id')
    
    if not all([user_id, device_id]):
        return jsonify({
            'success': False,
            'message': 'Eksik parametreler!'
        }), 400
    
    try:
        # Kullanıcıyı kontrol et
        user = db_session.query(User).filter(
            User.user_id == user_id,
            User.deleted_at.is_(None)
        ).first()
        
        if not user:
            return jsonify({
                'success': False,
                'message': 'Kullanıcı bulunamadı!'
            }), 404
        
        # Cihazı kontrol et
        device = db_session.query(Device).filter(
            Device.device_id == device_id,
            Device.deleted_at.is_(None),
            Device.is_active == True
        ).first()
        
        if not device:
            return jsonify({
                'success': False,
                'message': 'Cihaz bulunamadı!'
            }), 404
        
        # Cihaza bağlan
        device_manager = DeviceManager()
        conn = device_manager.get_connection(device.ip, device.port)
        
        if not conn:
            return jsonify({
                'success': False,
                'message': 'Cihaza bağlanılamadı!'
            }), 500
        
        try:
            # Parmak izini sil
            conn.delete_user_template(user_id)
            
            return jsonify({
                'success': True,
                'message': 'Parmak izi başarıyla silindi.'
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Parmak izi silinirken bir hata oluştu: {str(e)}'
            }), 500
            
        finally:
            conn.disconnect()
            
    except Exception as e:
        logger.error(f"Parmak izi silme hatası: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/fingerprint/sync', methods=['POST'])
@login_required
@admin_required
def sync_fingerprints():
    """Parmak izlerini senkronize et"""
    if not current_user.is_admin:
        return jsonify({
            'success': False,
            'message': 'Bu işlem için yetkiniz yok!'
        }), 403
    
    source_device_id = request.form.get('source_device_id')
    target_device_id = request.form.get('target_device_id')
    
    if not all([source_device_id, target_device_id]):
        return jsonify({
            'success': False,
            'message': 'Eksik parametreler!'
        }), 400
    
    if source_device_id == target_device_id:
        return jsonify({
            'success': False,
            'message': 'Kaynak ve hedef cihaz aynı olamaz!'
        }), 400
    
    try:
        # Cihazları kontrol et
        source_device = db_session.query(Device).filter(
            Device.device_id == source_device_id,
            Device.deleted_at.is_(None),
            Device.is_active == True
        ).first()
        
        target_device = db_session.query(Device).filter(
            Device.device_id == target_device_id,
            Device.deleted_at.is_(None),
            Device.is_active == True
        ).first()
        
        if not source_device or not target_device:
            return jsonify({
                'success': False,
                'message': 'Cihazlardan biri veya her ikisi bulunamadı!'
            }), 404
        
        # Cihazlara bağlan
        device_manager = DeviceManager()
        source_conn = device_manager.get_connection(source_device.ip, source_device.port)
        target_conn = device_manager.get_connection(target_device.ip, target_device.port)
        
        if not source_conn or not target_conn:
            return jsonify({
                'success': False,
                'message': 'Cihazlardan birine veya her ikisine bağlanılamadı!'
            }), 500
        
        try:
            # Kaynak cihazdaki parmak izlerini al
            templates = source_conn.get_templates()
            
            if not templates:
                return jsonify({
                    'success': False,
                    'message': 'Kaynak cihazda parmak izi bulunamadı!'
                }), 404
            
            # Hedef cihaza parmak izlerini aktar
            for template in templates:
                target_conn.set_user_template(template)
            
            return jsonify({
                'success': True,
                'message': f'{len(templates)} parmak izi başarıyla senkronize edildi.'
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Senkronizasyon sırasında bir hata oluştu: {str(e)}'
            }), 500
            
        finally:
            source_conn.disconnect()
            target_conn.disconnect()
            
    except Exception as e:
        logger.error(f"Parmak izi senkronizasyon hatası: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/profile', methods=['GET', 'POST'])
@login_required
@admin_or_supervisor_required
def profile():
    """Profil sayfası"""
    try:
        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            
            user = db_session.query(User).filter(
                User.user_id == current_user.id
            ).first()
            
            if current_password and new_password:
                if not verify_password(user.password, current_password):
                    flash('Mevcut şifre yanlış!', 'danger')
                    return redirect(url_for('profile'))
                
                # Yeni şifreyi hashle ve kaydet
                hashed_password = hash_password(new_password)
                user.password = hashed_password
                user.raw_password = new_password  # Ham şifreyi de kaydet
            
            user.name = name
            user.email = email
            
            try:
                db_session.commit()
                flash('Profil başarıyla güncellendi!', 'success')
            except Exception as e:
                db_session.rollback()
                flash(f'Hata: {str(e)}', 'danger')
                
        user = db_session.query(User).filter(
            User.user_id == current_user.id
        ).first()
        
        return render_template('profile.html', user=user)
    except Exception as e:
        logger.error(f"Profil sayfası hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return render_template('profile.html')

@app.route('/profile/update', methods=['POST'])
@login_required
@admin_or_supervisor_required
def update_profile():
    """Profil güncelleme"""
    name = request.form.get('name')
    email = request.form.get('email')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not all([name, email]):
        flash('Ad ve e-posta alanları zorunludur!', 'error')
        return redirect(url_for('profile'))
    
    try:
        # Kullanıcıyı al
        user = db_session.query(User).filter(
            User.user_id == current_user.id
        ).first()
        
        if not user:
            flash('Kullanıcı bulunamadı!', 'error')
            return redirect(url_for('index'))
        
        # E-posta kontrolü
        if email != user.email:
            existing_user = db_session.query(User).filter(
                User.email == email,
                User.user_id != user.user_id,
                User.deleted_at.is_(None)
            ).first()
            
            if existing_user:
                flash('Bu e-posta adresi başka bir kullanıcı tarafından kullanılıyor!', 'error')
                return redirect(url_for('profile'))
        
        # Şifre değişikliği kontrolü
        if current_password and new_password and confirm_password:
            if not verify_password(user.password, current_password):
                flash('Mevcut şifre yanlış!', 'error')
                return redirect(url_for('profile'))
            
            if new_password != confirm_password:
                flash('Yeni şifreler eşleşmiyor!', 'error')
                return redirect(url_for('profile'))
            
            if len(new_password) < 6:
                flash('Yeni şifre en az 6 karakter olmalıdır!', 'error')
                return redirect(url_for('profile'))
            
            # Şifreyi güncelle
            hashed_password = hash_password(new_password)
            user.password = hashed_password
            user.raw_password = new_password  # Ham şifreyi de kaydet
        
        # Diğer bilgileri güncelle
        user.name = name
        user.email = email
        user.updated_at = datetime.now()
        
        db_session.commit()
        flash('Profil bilgileriniz başarıyla güncellendi.', 'success')
        return redirect(url_for('profile'))
        
    except Exception as e:
        db_session.rollback()
        flash(f'Profil güncellenirken bir hata oluştu: {str(e)}', 'error')
        return redirect(url_for('profile'))

def initialize_database():
    """
    Veritabanını başlatır ve tabloları oluşturur.
    """
    try:
        # Base'den gelen tüm tabloları oluştur
        Base.metadata.create_all(bind=engine)
        current_app.logger.info("Veritabanı tabloları oluşturuldu")
        
        # Varsayılan rolleri ve admin kullanıcısını oluştur
        with Session() as session:
            Role.create_default_roles(session)
            User.create_default_admin(session)
            
        current_app.logger.info("Varsayılan roller ve admin kullanıcısı oluşturuldu")
        return True
    except Exception as e:
        current_app.logger.error(f"Veritabanı başlatma hatası: {str(e)}")
        return False

def reset_auto_increment(table_name):
    """
    Belirtilen tablonun auto increment değerini sıfırlar
    """
    try:
        with engine.connect() as connection:
            connection.execute(text(f"ALTER TABLE {table_name} AUTO_INCREMENT = 1"))
        return True
    except Exception as e:
        current_app.logger.error(f"Auto increment sıfırlama hatası ({table_name}): {str(e)}")
        return False

@click.command(name='init-app')
@with_appcontext
def init_app_command():
    """Uygulama başlatma komutları"""
    click.echo("Veritabanı başlatılıyor...")
    if initialize_database():
        click.echo("Veritabanı başarıyla başlatıldı!")
    else:
        click.echo("Veritabanı başlatılırken hata oluştu!")
        exit(1)

# Uygulama başlatma ve kapatma işlemleri
app.cli.add_command(init_app_command)

# Uygulama başlangıç ayarlarını yap
app.before_first_request(initialize)

@app.teardown_appcontext
def cleanup(exception=None):
    db_session.remove()

# Uygulama başlangıcı
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 

class DeviceManager:
    def __init__(self):
        self.connections = {}
        self.connected_ips = set()
        self.monitor_thread = None
        self.monitoring = False
        self.lock = threading.RLock()

    def start_monitoring(self):
        if self.monitoring:
            return
            
        self.monitoring = True
        
        def monitor_connections():
            while self.monitoring:
                try:
                    with self.lock:
                        # Veritabanından tüm aktif cihazları çek
                        with Session() as session:
                            devices = session.query(Device).filter_by(is_active=True).all()
                            
                        for device in devices:
                            # Son bağlantı durumunu kontrol et
                            is_connected = self.is_device_connected(device.ip)
                            # Durumu veritabanında güncelle
                            self.update_device_status_in_db(device.ip, is_connected)
                                
                except Exception as e:
                    current_app.logger.error(f"Bağlantı izleme hatası: {str(e)}")
                
                time.sleep(30)  # 30 saniyede bir kontrol et
                
        self.monitor_thread = threading.Thread(target=monitor_connections)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
            self.monitor_thread = None

    def disconnect_all(self):
        with self.lock:
            for ip in list(self.connections.keys()):
                self.disconnect_device(ip)
        self.connected_ips.clear()

    def disconnect_device(self, ip):
        with self.lock:
            if ip in self.connections:
                try:
                    conn = self.connections[ip]
                    conn.disconnect()
                    current_app.logger.info(f"Cihaz bağlantısı kapatıldı: {ip}")
                except Exception as e:
                    current_app.logger.error(f"Cihaz bağlantısını kapatırken hata: {ip}, {str(e)}")
                finally:
                    del self.connections[ip]
                    if ip in self.connected_ips:
                        self.connected_ips.remove(ip)

    def is_device_connected(self, ip):
        with self.lock:
            if ip not in self.connections:
                return False
                
            try:
                conn = self.connections[ip]
                conn.refresh_data()  # Bağlantıyı test et
                return True
            except Exception:
                # Bağlantı hatası, bağlantıyı kaldır
                self.disconnect_device(ip)
                return False

    def get_connection(self, ip, port=4370, force_new=False, timeout=5):
        with self.lock:
            # Eğer zorla yeni bağlantı isteniyorsa veya bağlantı yoksa
            if force_new or ip not in self.connections:
                if ip in self.connections:
                    # Mevcut bağlantıyı kapat
                    self.disconnect_device(ip)
                
                try:
                    # SQLAlchemy ile veritabanından cihaz bilgisini al
                    with Session() as session:
                        device = session.query(Device).filter_by(ip=ip).first()
                    
                    if not device:
                        raise ValueError(f"Cihaz bulunamadı: {ip}")
                    
                    # Yeni bağlantı oluştur (ZK kütüphanesi bağlantı hatalarını yakalar)
                    try:
                        zk = ZK(ip, port=port, timeout=timeout)
                        conn = zk.connect()
                        
                        if not conn:
                            raise ConnectionError(f"Cihaza bağlanılamadı: {ip}")
                            
                        self.connections[ip] = conn
                        self.connected_ips.add(ip)
                        
                        # Cihaz durumunu güncelle
                        self.update_device_status_in_db(ip, True)
                        current_app.logger.info(f"Cihaz bağlantısı kuruldu: {ip}")
                        
                        return conn
                    except Exception as inner_e:
                        current_app.logger.error(f"ZK bağlantı hatası: {ip}, {str(inner_e)}")
                        self.update_device_status_in_db(ip, False)
                        raise ConnectionError(f"Cihaz bağlantısı başarısız: {str(inner_e)}")
                    
                except Exception as e:
                    current_app.logger.error(f"Cihaz bağlantısı kurulamadı: {ip}, {str(e)}")
                    # Durumu güncellerken bile hata olabilir, bunu da ele al
                    try:
                        self.update_device_status_in_db(ip, False)
                    except Exception as db_error:
                        current_app.logger.error(f"Veritabanı güncellemesi başarısız: {str(db_error)}")
                    raise
            
            # Mevcut bağlantıyı döndür
            return self.connections[ip]

    def update_device_status_in_db(self, ip, is_connected):
        try:
            with Session() as session:
                device = session.query(Device).filter_by(ip=ip).first()
                if device:
                    device.last_status = "Connected" if is_connected else "Disconnected"
                    device.last_connection = datetime.now() if is_connected else device.last_connection
                    session.commit()
        except Exception as e:
            current_app.logger.error(f"Cihaz durumu güncellenirken hata: {ip}, {str(e)}")

    def connect_all_devices(self):
        with Session() as session:
            devices = session.query(Device).filter_by(is_active=True).all()
            
        for device in devices:
            try:
                self.get_connection(device.ip, port=device.port, timeout=device.timeout)
            except Exception:
                pass  # Hatalar zaten get_connection içinde loglanıyor

# Global cihaz yöneticisi
device_manager = DeviceManager()

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_or_supervisor_required
def delete_user(user_id):
    """Kullanıcı silme işlevi"""
    try:
        with Session() as session:
            # Silinecek kullanıcıyı bul
            user = session.query(User).filter_by(user_id=user_id).first()
            
            if not user:
                flash('Kullanıcı bulunamadı', 'danger')
                return redirect(url_for('users'))
                
            # Kullanıcıya ait kayıtları ve cihaz kullanıcı ilişkilerini sil
            session.query(Record).filter_by(user_id=user_id).delete()
            
            # Kullanıcıyı sil
            session.delete(user)
            session.commit()
            
            flash('Kullanıcı başarıyla silindi', 'success')
            
    except Exception as e:
        current_app.logger.error(f"Kullanıcı silme hatası: {str(e)}")
        flash(f'Kullanıcı silinirken hata oluştu: {str(e)}', 'danger')
        
    return redirect(url_for('users'))

@app.route('/records/delete/<int:record_id>', methods=['POST'])
@login_required
@admin_or_supervisor_required
def delete_record(record_id):
    """Kayıt silme işlevi"""
    try:
        with Session() as session:
            # Silinecek kaydı bul
            record = session.query(Record).filter_by(id=record_id).first()
            
            if not record:
                flash('Kayıt bulunamadı', 'danger')
                return redirect(url_for('records'))
                
            # Kaydı sil
            session.delete(record)
            session.commit()
            
            flash('Kayıt başarıyla silindi', 'success')
            
    except Exception as e:
        current_app.logger.error(f"Kayıt silme hatası: {str(e)}")
        flash(f'Kayıt silinirken hata oluştu: {str(e)}', 'danger')
        
    return redirect(url_for('records'))

@app.route('/records/delete-all', methods=['POST'])
@login_required
@admin_or_supervisor_required
def delete_all_records():
    """Tüm kayıtları silme işlevi"""
    try:
        with Session() as session:
            # Tüm kayıtları sil
            session.query(Record).delete()
            session.commit()
            
            # Auto increment değerini sıfırla
            reset_auto_increment('records')
            
            flash('Tüm kayıtlar başarıyla silindi', 'success')
            
    except Exception as e:
        current_app.logger.error(f"Tüm kayıtları silme hatası: {str(e)}")
        flash(f'Kayıtlar silinirken hata oluştu: {str(e)}', 'danger')
        
    return redirect(url_for('records'))

def cleanup_connections():
    """Tüm cihaz bağlantılarını kapatır"""
    try:
        device_manager.disconnect_all()
        current_app.logger.info("Tüm cihaz bağlantıları kapatıldı")
    except Exception as e:
        current_app.logger.error(f"Bağlantıları kapatırken hata: {str(e)}")

def shutdown_server():
    """Flask uygulamasını kapatır"""
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Sunucu Werkzeug tarafından çalıştırılmıyor, kapatılamıyor')
    func()

@app.route('/shutdown', methods=['POST'])
@login_required
@admin_or_supervisor_required
def shutdown():
    """Sunucuyu kapatma endpoint'i"""
    # Oturumu kapat
    logout_user()
    
    # Bağlantıları temizle
    cleanup_connections()
    
    # Sunucuyu kapat
    shutdown_server()
    return 'Sunucu kapatılıyor...'

# ZK bağlantı fonksiyonu
def connect(ip, port=4370, timeout=5):
    zk = ZK(ip, port=port, timeout=timeout)
    conn = zk.connect()
    return conn

@app.route('/api/records/search')
@login_required
@admin_or_supervisor_required
def api_search_records():
    try:
        search_term = request.args.get('q', '')
        page = request.args.get('page', 1, type=int)
        per_page = 30
        
        query = db_session.query(Record, User, Device)\
            .join(User, Record.user_id == User.user_id)\
            .outerjoin(Device, Record.device_id == Device.device_id)\
            .filter(
                Record.deleted_at.is_(None),
                or_(
                    User.name.ilike(f'%{search_term}%'),
                    cast(User.user_id, String).ilike(f'%{search_term}%'),
                    User.card_no.ilike(f'%{search_term}%')
                )
            )\
            .order_by(Record.id.desc())
        
        total = query.count()
        raw_records = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Row objectlerini tuple'a çevir
        records = []
        for row in raw_records:
            if hasattr(row, '_mapping') or hasattr(row, '__getitem__'):
                try:
                    record_obj = row[0] if len(row) > 0 else None
                    user_obj = row[1] if len(row) > 1 else None
                    device_obj = row[2] if len(row) > 2 else None
                    records.append((record_obj, user_obj, device_obj))
                except (IndexError, TypeError):
                    records.append(row)
            else:
                records.append(row)
        
        # Debug için ilk kaydın türünü kontrol et (API search için)
        if records:
            first_item = records[0]
            logger.info(f"API Search Records tuple türü: {type(first_item)}")
        
        return jsonify({
            'success': True,
            'records': [{
                'id': record.id,
                'user_name': user.name,
                'user_id': user.user_id,
                'card_no': user.card_no,
                'timestamp': record.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'status': record.status,
                'punch': record.punch,
                'device_name': device.name if device else None
            } for record, user, device in records],
            'total': total,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        logger.error(f"API kayıt arama hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove() 

@app.route('/device-users')
@login_required
@admin_required
def device_users():
    """Cihaz-Kullanıcı Atama Yönetimi"""
    try:
        logger.info("Device-users sayfası yükleniyor...")
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        logger.info(f"Sayfa: {page}, Sayfa başına: {per_page}")
        
        # Device-User ilişkilerini al (JOIN ile)
        logger.info("DeviceUser, User, Device JOIN sorgusu hazırlanıyor...")
        query = db_session.query(DeviceUser, User, Device)\
            .join(User, DeviceUser.user_id == User.user_id)\
            .join(Device, DeviceUser.device_id == Device.device_id)\
            .order_by(User.user_id.asc(), DeviceUser.device_user_id.asc())
        
        logger.info("Toplam kayıt sayısı hesaplanıyor...")
        total = query.count()
        logger.info(f"Toplam kayıt sayısı: {total}")
        
        logger.info("Sayfalama uygulanıyor...")
        device_user_records = query.offset((page - 1) * per_page).limit(per_page).all()
        logger.info(f"Sayfalama sonucu: {len(device_user_records)} kayıt alındı")
        
        # Aktif atama sayısını hesapla (tüm kayıtlarda)
        logger.info("Aktif atama sayısı hesaplanıyor...")
        active_assignments = db_session.query(DeviceUser)\
            .filter(DeviceUser.status == 1)\
            .count()
        logger.info(f"Aktif atamalar: {active_assignments}")
        
        # Pasif atama sayısını hesapla (tüm kayıtlarda)
        logger.info("Pasif atama sayısı hesaplanıyor...")
        passive_assignments = db_session.query(DeviceUser)\
            .filter(DeviceUser.status == 0)\
            .count()
        logger.info(f"Pasif atamalar: {passive_assignments}")
        
        # Kullanıcıları ve cihazları da al (dropdown'lar için)
        logger.info("Kullanıcılar sorgulanıyor...")
        users = db_session.query(User)\
            .filter(User.deleted_at.is_(None))\
            .order_by(User.name)\
            .all()
        logger.info(f"Kullanıcı sayısı: {len(users)}")
        
        logger.info("Cihazlar sorgulanıyor...")
        devices = db_session.query(Device)\
            .filter(Device.deleted_at.is_(None))\
            .order_by(Device.name)\
            .all()
        logger.info(f"Cihaz sayısı: {len(devices)}")
        
        logger.info("Template render ediliyor...")
        return render_template(
            'device_users.html',
            device_user_records=device_user_records,
            users=users,
            devices=devices,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
            search_term='',
            status_filter='',
            is_search=False,
            active_assignments=active_assignments,
            passive_assignments=passive_assignments
        )
    except Exception as e:
        logger.error(f"Device-User sayfası hatası: {str(e)}")
        logger.error(f"Hata detayı: {type(e).__name__}")
        import traceback
        logger.error(f"Stack trace: {traceback.format_exc()}")
        flash(f'Bir hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('index'))
    finally:
        logger.info("Device-users fonksiyonu tamamlandı, session temizleniyor...")
        db_session.remove()

@app.route('/device-users/add', methods=['POST'])
@login_required
@admin_required
def add_device_user():
    """Kullanıcıyı Cihaza Ata"""
    try:
        user_id = request.form.get('user_id', type=int)
        device_id = request.form.get('device_id', type=int)
        status = request.form.get('status', 1, type=int)
        
        if not user_id or not device_id:
            flash('Kullanıcı ve cihaz seçimi zorunludur!', 'warning')
            return redirect(url_for('device_users'))
        
        # Aynı atama var mı kontrol et
        existing = db_session.query(DeviceUser)\
            .filter(
                DeviceUser.user_id == user_id,
                DeviceUser.device_id == device_id
            ).first()
            
        if existing:
            flash('Bu kullanıcı zaten bu cihaza atanmış!', 'warning')
            return redirect(url_for('device_users'))
        
        # Yeni atama oluştur
        new_assignment = DeviceUser(
            user_id=user_id,
            device_id=device_id,
            status=status
        )
        
        db_session.add(new_assignment)
        db_session.commit()
        
        flash('Kullanıcı başarıyla cihaza atandı!', 'success')
        return redirect(url_for('device_users'))
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"Device-User ekleme hatası: {str(e)}")
        flash(f'Atama sırasında hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('device_users'))
    finally:
        db_session.remove()

@app.route('/device-users/delete/<int:device_user_id>', methods=['POST'])
@login_required
@admin_required
def delete_device_user(device_user_id):
    """Cihaz-Kullanıcı Atamasını Sil"""
    try:
        assignment = db_session.query(DeviceUser)\
            .filter(DeviceUser.device_user_id == device_user_id)\
            .first()
            
        if not assignment:
            flash('Atama bulunamadı!', 'danger')
            return redirect(url_for('device_users'))
        
        db_session.delete(assignment)
        db_session.commit()
        
        flash('Atama başarıyla silindi!', 'success')
        return redirect(url_for('device_users'))
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"Device-User silme hatası: {str(e)}")
        flash(f'Atama silinirken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('device_users'))
    finally:
        db_session.remove()

@app.route('/device-users/toggle-status/<int:device_user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_device_user_status(device_user_id):
    """Cihaz-Kullanıcı Durumunu Değiştir"""
    try:
        assignment = db_session.query(DeviceUser)\
            .filter(DeviceUser.device_user_id == device_user_id)\
            .first()
            
        if not assignment:
            flash('Atama bulunamadı!', 'danger')
            return redirect(url_for('device_users'))
        
        # Status'u değiştir (0 -> 1, 1 -> 0)
        assignment.status = 1 if assignment.status == 0 else 0
        assignment.updated_at = datetime.now()
        
        db_session.commit()
        
        status_text = "Aktif" if assignment.status == 1 else "Pasif"
        flash(f'Atama durumu {status_text} olarak güncellendi!', 'success')
        return redirect(url_for('device_users'))
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"Device-User status değiştirme hatası: {str(e)}")
        flash(f'Durum değiştirilirken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('device_users'))
    finally:
        db_session.remove()

@app.route('/device-users/search')
@login_required
@admin_required
def search_device_users():
    """Cihaz-Kullanıcı Atamaları Arama"""
    try:
        search_term = request.args.get('q', '').strip()
        status_filter = request.args.get('status', '')
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Base query
        query = db_session.query(DeviceUser, User, Device)\
            .join(User, DeviceUser.user_id == User.user_id)\
            .join(Device, DeviceUser.device_id == Device.device_id)
        
        # Arama filtresi
        if search_term:
            query = query.filter(
                or_(
                    User.name.ilike(f'%{search_term}%'),
                    cast(User.user_id, String).ilike(f'%{search_term}%'),
                    Device.name.ilike(f'%{search_term}%'),
                    Device.ip.ilike(f'%{search_term}%'),
                    cast(DeviceUser.device_user_id, String).ilike(f'%{search_term}%')
                )
            )
        
        # Durum filtresi
        if status_filter and status_filter in ['0', '1']:
            query = query.filter(DeviceUser.status == int(status_filter))
        
        # Sıralama
        query = query.order_by(User.user_id.asc(), DeviceUser.device_user_id.asc())
        
        total = query.count()
        device_user_records = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Aktif atama sayısını hesapla (tüm kayıtlarda, filtresiz)
        active_assignments = db_session.query(DeviceUser)\
            .filter(DeviceUser.status == 1)\
            .count()
        
        # Pasif atama sayısını hesapla (tüm kayıtlarda, filtresiz)
        passive_assignments = db_session.query(DeviceUser)\
            .filter(DeviceUser.status == 0)\
            .count()
        
        # Kullanıcıları ve cihazları da al (dropdown'lar için)
        users = db_session.query(User)\
            .filter(User.deleted_at.is_(None))\
            .order_by(User.name)\
            .all()
            
        devices = db_session.query(Device)\
            .filter(Device.deleted_at.is_(None))\
            .order_by(Device.name)\
            .all()
        
        return render_template(
            'device_users.html',
            device_user_records=device_user_records,
            users=users,
            devices=devices,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=(total + per_page - 1) // per_page,
            search_term=search_term,
            status_filter=status_filter,
            is_search=True,
            active_assignments=active_assignments,
            passive_assignments=passive_assignments
        )
    except Exception as e:
        logger.error(f"Device-User arama hatası: {str(e)}")
        flash('Arama sırasında bir hata oluştu!', 'danger')
        return redirect(url_for('device_users'))
    finally:
        db_session.remove()

# Device CRUD API'ları
@app.route('/api/devices/<int:device_id>', methods=['GET'])
@login_required
@admin_required
def get_device(device_id):
    """Tek cihaz bilgilerini getir"""
    try:
        device = db_session.query(Device)\
            .filter(
                Device.device_id == device_id,
                Device.deleted_at.is_(None)
            ).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Cihaz bulunamadı!'})
        
        device_data = {
            'device_id': device.device_id,
            'name': device.name,
            'ip': device.ip,
            'port': device.port,
            'timeout': device.timeout or 5,
            'is_active': device.is_active,
            'description': getattr(device, 'description', ''),
            'department_id': getattr(device, 'department_id', None),
            'location_id': getattr(device, 'location_id', None),
            'last_connection': device.last_connection.strftime('%d.%m.%Y %H:%M') if device.last_connection else None,
            'last_status': device.last_status
        }
        
        return jsonify({'success': True, 'device': device_data})
        
    except Exception as e:
        logger.error(f"Cihaz bilgisi getirme hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()

@app.route('/api/devices/<int:device_id>', methods=['PUT'])
@login_required
@admin_required
def update_device(device_id):
    """Cihaz bilgilerini güncelle"""
    try:
        device = db_session.query(Device)\
            .filter(
                Device.device_id == device_id,
                Device.deleted_at.is_(None)
            ).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Cihaz bulunamadı!'})
        
        data = request.get_json()
        
        # Güncellenecek alanları kontrol et
        if 'name' in data:
            device.name = data['name']
        if 'ip' in data:
            device.ip = data['ip']
        if 'port' in data:
            device.port = int(data['port'])
        if 'timeout' in data:
            device.timeout = int(data['timeout'])
        if 'is_active' in data:
            device.is_active = bool(data['is_active'])
        if 'description' in data and hasattr(device, 'description'):
            device.description = data['description']
        if 'department_id' in data and hasattr(device, 'department_id'):
            device.department_id = data['department_id']
        if 'location_id' in data and hasattr(device, 'location_id'):
            device.location_id = data['location_id']
            
        device.updated_at = datetime.now()
        db_session.commit()
        
        return jsonify({'success': True, 'message': 'Cihaz başarıyla güncellendi!'})
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"Cihaz güncelleme hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()

@app.route('/api/devices', methods=['POST'])
@login_required
@admin_required
def create_device():
    """Yeni cihaz ekle"""
    try:
        data = request.get_json()
        
        # Zorunlu alanları kontrol et
        required_fields = ['name', 'ip', 'port']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'success': False, 'message': f'{field} alanı zorunludur!'})
        
        # IP kontrolü - aynı IP'de cihaz var mı?
        existing_device = db_session.query(Device)\
            .filter(
                Device.ip == data['ip'],
                Device.deleted_at.is_(None)
            ).first()
        
        if existing_device:
            return jsonify({'success': False, 'message': 'Bu IP adresi zaten kullanılıyor!'})
        
        # Yeni cihaz oluştur
        device_kwargs = {
            'name': data['name'],
            'ip': data['ip'],
            'port': int(data['port']),
            'timeout': int(data.get('timeout', 5)),
            'is_active': bool(data.get('is_active', True))
        }
        
        # Opsiyonel alanları kontrol ederek ekle
        if 'description' in data:
            device_kwargs['description'] = data['description']
        if 'department_id' in data and data['department_id']:
            device_kwargs['department_id'] = data['department_id']
        if 'location_id' in data and data['location_id']:
            device_kwargs['location_id'] = data['location_id']
            
        new_device = Device(**device_kwargs)
        
        db_session.add(new_device)
        db_session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Cihaz başarıyla eklendi!',
            'device_id': new_device.device_id
        })
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"Cihaz ekleme hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()

@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_device(device_id):
    """Cihazı sil (soft delete)"""
    try:
        device = db_session.query(Device)\
            .filter(
                Device.device_id == device_id,
                Device.deleted_at.is_(None)
            ).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Cihaz bulunamadı!'})
        
        # Soft delete
        device.deleted_at = datetime.now()
        db_session.commit()
        
        return jsonify({'success': True, 'message': 'Cihaz başarıyla silindi!'})
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"Cihaz silme hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()

@app.route('/api/devices/<int:device_id>/test-connection', methods=['POST'])
@login_required
@admin_required
def test_device_connection(device_id):
    """Cihaz bağlantısını test et"""
    try:
        device = db_session.query(Device)\
            .filter(
                Device.device_id == device_id,
                Device.deleted_at.is_(None)
            ).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Cihaz bulunamadı!'})
        
        # Bağlantıyı test et
        from zk import ZK
        
        zk = ZK(device.ip, port=device.port, timeout=device.timeout or 5)
        try:
            conn = zk.connect()
            if conn:
                # Cihaz bilgilerini al
                firmware = conn.get_firmware_version()
                serialnumber = conn.get_serialnumber()
                users_count = len(conn.get_users())
                attendance_count = len(conn.get_attendance())
                
                # Bağlantıyı kapat
                conn.disconnect()
                
                # Database'i güncelle
                device.last_connection = datetime.now()
                device.last_status = 'connected'
                db_session.commit()
                
                return jsonify({
                    'success': True,
                    'message': 'Bağlantı başarılı!',
                    'device_info': {
                        'firmware': firmware,
                        'serial_number': serialnumber,
                        'users_count': users_count,
                        'attendance_count': attendance_count
                    }
                })
            else:
                device.last_status = 'disconnected'
                db_session.commit()
                return jsonify({'success': False, 'message': 'Cihaza bağlanılamadı!'})
                
        except Exception as e:
            device.last_status = 'error'
            db_session.commit()
            return jsonify({'success': False, 'message': f'Bağlantı hatası: {str(e)}'})
            
    except Exception as e:
        logger.error(f"Cihaz bağlantı test hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()

@app.route('/api/devices/<int:device_id>/connect-alt')
@login_required
@admin_required
def connect_device_alt(device_id):
    try:
        device = db_session.query(Device)\
            .filter(
                Device.device_id == device_id,
                Device.deleted_at.is_(None)
            ).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Cihaz bulunamadı!'})
        
        # Cihaz bağlantısını yap
        zk = ZK(device.ip, port=device.port, timeout=device.timeout)
        conn = zk.connect()
        
        if conn:
            device.last_status = 'connected'
            device.last_connection = datetime.now()
            db_session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Cihaz bağlantısı başarılı!'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Cihaza bağlanılamadı!'
            })
            
    except Exception as e:
        logger.error(f"Cihaz bağlantı hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()

# Cihaz İşlemleri API'ları
@app.route('/api/devices/<int:device_id>/sync', methods=['POST'])
@login_required
@admin_required
def sync_device_data(device_id):
    """Cihaz verilerini senkronize et"""
    try:
        device = db_session.query(Device)\
            .filter(
                Device.device_id == device_id,
                Device.deleted_at.is_(None)
            ).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Cihaz bulunamadı!'})
        
        from zk import ZK
        
        zk = ZK(device.ip, port=device.port, timeout=device.timeout or 5)
        try:
            conn = zk.connect()
            if not conn:
                return jsonify({'success': False, 'message': 'Cihaza bağlanılamadı!'})
            
            # Kullanıcıları senkronize et
            device_users = conn.get_users()
            synced_users = 0
            
            for device_user in device_users:
                # Database'de kullanıcı var mı kontrol et
                existing_user = db_session.query(User)\
                    .filter(User.user_id == device_user.uid).first()
                
                if not existing_user:
                    # Yeni kullanıcı oluştur
                    new_user = User(
                        user_id=device_user.uid,
                        name=device_user.name or f'User_{device_user.uid}',
                        card_no=device_user.card,
                        device_role=device_user.privilege,
                        status=1
                    )
                    db_session.add(new_user)
                    synced_users += 1
            
            # Kayıtları senkronize et
            attendance_records = conn.get_attendance()
            synced_records = 0
            
            for record in attendance_records:
                # Aynı kayıt var mı kontrol et
                existing_record = db_session.query(Record)\
                    .filter(
                        Record.user_id == record.uid,
                        Record.timestamp == record.timestamp,
                        Record.device_id == device_id
                    ).first()
                
                if not existing_record:
                    new_record = Record(
                        user_id=record.uid,
                        timestamp=record.timestamp,
                        punch=record.punch,
                        status=record.status if hasattr(record, 'status') else None,
                        device_id=device_id,
                        is_synced=True
                    )
                    db_session.add(new_record)
                    synced_records += 1
            
            conn.disconnect()
            db_session.commit()
            
            # Device durumunu güncelle
            device.last_connection = datetime.now()
            device.last_status = 'connected'
            db_session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Senkronizasyon tamamlandı! {synced_users} kullanıcı, {synced_records} kayıt senkronize edildi.'
            })
            
        except Exception as e:
            if 'conn' in locals():
                conn.disconnect()
            return jsonify({'success': False, 'message': f'Senkronizasyon hatası: {str(e)}'})
            
    except Exception as e:
        logger.error(f"Cihaz senkronizasyon hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()

@app.route('/api/devices/<int:device_id>/clear', methods=['POST'])
@login_required
@admin_required
def clear_device_records(device_id):
    """Cihaz kayıtlarını temizle"""
    try:
        device = db_session.query(Device)\
            .filter(
                Device.device_id == device_id,
                Device.deleted_at.is_(None)
            ).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Cihaz bulunamadı!'})
        
        from zk import ZK
        
        zk = ZK(device.ip, port=device.port, timeout=device.timeout or 5)
        try:
            conn = zk.connect()
            if not conn:
                return jsonify({'success': False, 'message': 'Cihaza bağlanılamadı!'})
            
            # Cihaz üzerindeki kayıtları temizle
            conn.clear_attendance()
            conn.disconnect()
            
            # Device durumunu güncelle
            device.last_connection = datetime.now()
            device.last_status = 'connected'
            db_session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Cihaz kayıtları başarıyla temizlendi!'
            })
            
        except Exception as e:
            if 'conn' in locals():
                conn.disconnect()
            return jsonify({'success': False, 'message': f'Kayıt temizleme hatası: {str(e)}'})
            
    except Exception as e:
        logger.error(f"Cihaz kayıt temizleme hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()

@app.route('/api/devices/<int:device_id>/restart', methods=['POST'])
@login_required
@admin_required
def restart_device(device_id):
    """Cihazı yeniden başlat"""
    try:
        device = db_session.query(Device)\
            .filter(
                Device.device_id == device_id,
                Device.deleted_at.is_(None)
            ).first()
        
        if not device:
            return jsonify({'success': False, 'message': 'Cihaz bulunamadı!'})
        
        from zk import ZK
        
        zk = ZK(device.ip, port=device.port, timeout=device.timeout or 5)
        try:
            conn = zk.connect()
            if not conn:
                return jsonify({'success': False, 'message': 'Cihaza bağlanılamadı!'})
            
            # Cihazı yeniden başlat
            conn.restart()
            conn.disconnect()
            
            # Device durumunu güncelle
            device.last_connection = datetime.now()
            device.last_status = 'restarting'
            db_session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Cihaz yeniden başlatma komutu gönderildi!'
            })
            
        except Exception as e:
            if 'conn' in locals():
                conn.disconnect()
            return jsonify({'success': False, 'message': f'Yeniden başlatma hatası: {str(e)}'})
            
    except Exception as e:
        logger.error(f"Cihaz yeniden başlatma hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})
    finally:
        db_session.remove()