from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Time, Text, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import os
import hashlib
from datetime import datetime

Base = declarative_base()

class Role(Base):
    __tablename__ = 'roles'
    
    role_id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime)
    
    users = relationship('User', back_populates='role')
    
    @staticmethod
    def create_default_roles(session):
        default_roles = ['Admin', 'Supervisor', 'User']
        for role_name in default_roles:
            if not session.query(Role).filter_by(name=role_name).first():
                role = Role(name=role_name)
                session.add(role)
        session.commit()

class Department(Base):
    __tablename__ = 'departments'
    
    department_id = Column(Integer, primary_key=True)
    department_name = Column(String(100), nullable=False)
    work_start_time = Column(Time)
    work_end_time = Column(Time)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime)
    
    users = relationship('User', back_populates='department')

class Location(Base):
    __tablename__ = 'locations'
    
    location_id = Column(Integer, primary_key=True)
    location_name = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime)
    
    devices = relationship('Device', back_populates='location')

class Device(Base):
    __tablename__ = 'devices'
    
    device_id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    ip = Column(String(15), nullable=False)
    port = Column(Integer, default=4370)
    timeout = Column(Integer, default=5)
    location_id = Column(Integer, ForeignKey('locations.location_id'))
    is_active = Column(Boolean, default=True)
    description = Column(Text, nullable=True)
    last_status = Column(String(20))
    last_connection = Column(DateTime)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime)
    
    location = relationship('Location', back_populates='devices')
    records = relationship('Record', back_populates='device')

class User(Base):
    __tablename__ = 'users'
    
    user_id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(256), nullable=False)  # Hashed password
    raw_password = Column(String(255))  # Ham şifre
    role_id = Column(Integer, ForeignKey('roles.role_id'))
    department_id = Column(Integer, ForeignKey('departments.department_id'))
    card_no = Column(String(50))
    device_role = Column(Integer, default=0)  # 0: Normal, 14: Admin, 3: Kayıt
    status = Column(Integer, default=1)  # 0: Pasif, 1: Aktif
    
    # Kimlik ve iletişim bilgileri
    TCKN = Column(String(11))  # TC Kimlik No
    phone_number = Column(String(15))  # Telefon numarası
    phone_no_country_code = Column(String(5))  # Ülke kodu
    
    # İş tarihleri
    start_date = Column(DateTime, nullable=True)  # İşe başlangıç tarihi
    end_date = Column(DateTime, nullable=True)  # İşten çıkış tarihi
    
    # Ek personel bilgileri
    gender = Column(String(20))
    occupation = Column(String(100))
    job_title = Column(String(100))
    nationality = Column(String(50))
    education_level = Column(String(50))
    work_type = Column(String(50))
    employment_status = Column(String(50))
    group_id = Column(Integer)
    last_update = Column(DateTime)
    
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime)
    
    role = relationship('Role', back_populates='users')
    department = relationship('Department', back_populates='users')
    records = relationship('Record', back_populates='user')
    leave_requests = relationship('LeaveRequest', foreign_keys='LeaveRequest.user_id', back_populates='user')
    approved_requests = relationship('LeaveRequest', foreign_keys='LeaveRequest.approved_by', back_populates='approver')
    
    @property
    def card(self):
        """Template uyumluluğu için card property'si"""
        return self.card_no
    
    @card.setter
    def card(self, value):
        self.card_no = value
    
    @staticmethod
    def create_default_admin(session):
        if not session.query(User).filter_by(email='admin@admin.com').first():
            # Admin rolünü bul
            admin_role = session.query(Role).filter_by(name='Admin').first()
            if not admin_role:
                return
            
            # Şifreyi hashle
            salt = os.urandom(32)
            key = hashlib.pbkdf2_hmac(
                'sha256',
                'admin'.encode('utf-8'),
                salt,
                100000
            )
            password = (salt + key).hex()
            
            # Admin kullanıcısını oluştur
            admin = User(
                user_id=1,
                name='Admin',
                email='admin@admin.com',
                password=password,
                role_id=admin_role.role_id,
                device_role=14,
                status=1
            )
            session.add(admin)
            session.commit()

class DeviceUser(Base):
    __tablename__ = 'device_users'
    
    device_user_id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('devices.device_id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    status = Column(Integer, default=1)  # 0: Pasif, 1: Aktif
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # İlişkiler
    device = relationship('Device')
    user = relationship('User')

class Record(Base):
    __tablename__ = 'records'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    device_id = Column(Integer, ForeignKey('devices.device_id'))
    timestamp = Column(DateTime, nullable=False)
    punch = Column(Integer)  # 0: Giriş, 1: Çıkış
    status = Column(String(50))
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime)
    
    user = relationship('User', back_populates='records')
    device = relationship('Device', back_populates='records')

class LeaveRequest(Base):
    __tablename__ = 'leave_requests'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    start_date = Column(DateTime, nullable=False)  # İzin başlangıç tarihi
    end_date = Column(DateTime, nullable=False)    # İzin bitiş tarihi
    reason = Column(Text, nullable=False)          # İzin sebebi
    status = Column(String(20), default='bekleniyor', nullable=False)  # bekleniyor, onaylandı, reddedildi
    request_date = Column(DateTime, default=datetime.now, nullable=False)  # Talep tarihi
    approved_by = Column(Integer, ForeignKey('users.user_id'), nullable=True)  # Onaylayan admin
    approved_date = Column(DateTime, nullable=True)  # Onaylanma tarihi
    admin_notes = Column(Text, nullable=True)      # Admin notları
    leave_type = Column(String(50), default='Yıllık İzin')  # İzin türü
    days_count = Column(Integer, nullable=True)    # İzin gün sayısı
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime)
    
    # İlişkiler
    user = relationship('User', foreign_keys=[user_id])
    approver = relationship('User', foreign_keys=[approved_by])
    
    def calculate_days(self):
        """İzin gün sayısını hesapla"""
        if self.start_date and self.end_date:
            delta = self.end_date - self.start_date
            return delta.days + 1  # Başlangıç günü dahil
        return 0
    
    @property
    def status_display(self):
        """Durum metni Türkçe"""
        status_map = {
            'bekleniyor': 'Bekleniyor',
            'onaylandı': 'Onaylandı', 
            'reddedildi': 'Reddedildi'
        }
        return status_map.get(self.status, self.status)
    
    @property
    def status_color(self):
        """Durum rengini döndür"""
        color_map = {
            'bekleniyor': 'warning',
            'onaylandı': 'success',
            'reddedildi': 'danger'
        }
        return color_map.get(self.status, 'secondary') 