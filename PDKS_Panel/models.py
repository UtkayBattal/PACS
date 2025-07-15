from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Time, Text, event, BigInteger, SmallInteger, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import hashlib
import os

Base = declarative_base()

class Role(Base):
    __tablename__ = 'roles'
    
    role_id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, default=0)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime, nullable=True)

    users = relationship("User", back_populates="role")

class Department(Base):
    __tablename__ = 'departments'
    
    department_id = Column(Integer, primary_key=True)
    department_key = Column(String(100), unique=True)
    department_name = Column(String(150))
    work_start_time = Column(Time)
    work_end_time = Column(Time)
    late_tolerance_minutes = Column(Integer)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime, nullable=True)

    users = relationship("User", back_populates="department")
    devices = relationship("Device", back_populates="department")

class Location(Base):
    __tablename__ = 'locations'
    
    location_id = Column(Integer, primary_key=True)
    location_name = Column(String(150), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime, nullable=True)

    devices = relationship("Device", back_populates="location")

class Device(Base):
    __tablename__ = 'devices'
    
    device_id = Column(Integer, primary_key=True)
    name = Column(String(100))
    ip = Column(String(100))
    port = Column(Integer)
    department_id = Column(Integer, ForeignKey('departments.department_id'))
    timeout = Column(Integer)
    is_active = Column(Boolean, default=True)
    description = Column(Text, nullable=True)
    location_id = Column(Integer, ForeignKey('locations.location_id'))
    last_connection = Column(DateTime)
    last_status = Column(String(50))
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime, nullable=True)

    department = relationship("Department", back_populates="devices")
    location = relationship("Location", back_populates="devices")
    records = relationship("Record", back_populates="device")
    device_users = relationship("CjDeviceUser", back_populates="device")

class User(Base):
    __tablename__ = 'users'
    
    user_id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    card_no = Column(String(50))
    device_role = Column(Integer)
    group_id = Column(Integer)
    last_update = Column(DateTime)
    gender = Column(String(20))
    occupation = Column(String(100))
    job_title = Column(String(100))
    nationality = Column(String(100))
    education_level = Column(String(100))
    department_id = Column(Integer, ForeignKey('departments.department_id'))
    work_type = Column(String(50))
    employment_status = Column(String(50))
    role_id = Column(Integer, ForeignKey('roles.role_id'))
    saysis_reference_id = Column(Integer, nullable=True)
    TCKN = Column(String(50))
    email = Column(String(255), unique=True)
    password = Column(String(255))  # Hashed password
    raw_password = Column(String(255))
    phone_number = Column(String(50))
    phone_no_country_code = Column(String(50))
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    saysis_integration = Column(Boolean, default=False)
    status = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime, nullable=True)

    department = relationship("Department", back_populates="users")
    role = relationship("Role", back_populates="users")
    records = relationship("Record", back_populates="user")
    device_users = relationship("CjDeviceUser", back_populates="user")

class Record(Base):
    __tablename__ = 'records'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    timestamp = Column(DateTime, nullable=False)
    status = Column(String(50))
    punch = Column(Integer)  # 0 = giriş, 1 = çıkış
    is_synced = Column(Boolean, default=False)
    device_id = Column(Integer, ForeignKey('devices.device_id'))
    verified = Column(Boolean, default=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    deleted_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="records")
    device = relationship("Device", back_populates="records")
    
class DeviceUser(Base):
    __tablename__ = 'device_users'

    device_user_id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(BigInteger, ForeignKey('devices.device_id'), nullable=False)
    user_id = Column(BigInteger, ForeignKey('users.user_id'), nullable=False)
    status = Column(SmallInteger, nullable=False, default=0)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # İlişkiler
    device = relationship('Device', back_populates='device_users')
    user = relationship('User', back_populates='device_users')