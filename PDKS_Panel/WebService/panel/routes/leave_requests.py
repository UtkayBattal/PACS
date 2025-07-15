from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
from functools import wraps
from sqlalchemy import func, and_, or_, desc
from sqlalchemy.orm import joinedload
from panel.models import User, LeaveRequest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import os
from datetime import datetime, timedelta
import logging

# Database bağlantısı
db_user = os.environ.get('DB_USER', 'dbuser')
db_password = os.environ.get('DB_PASSWORD', 'dbpass123')
db_host = os.environ.get('DB_HOST', 'pdks_database')
db_port = os.environ.get('DB_PORT', '5433')
db_name = os.environ.get('DB_NAME', 'myapp_db')

DATABASE_URL = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
db_session = scoped_session(SessionLocal)

# Logger konfigürasyonu
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

leave_requests = Blueprint('leave_requests', __name__, url_prefix='/leave-requests')

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
    """Employee (role_id = 3) ve Supervisor (role_id = 2) kullanıcıları için decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        # Role_id 2 (Supervisor) ve 3 (Employee) olan kullanıcılar erişebilir
        if current_user.role_id not in [2, 3]:
            logger.warning(f"Yetkisiz erişim - User: {current_user.email}, Role: {current_user.role_id}")
            flash('Bu sayfaya erişim yetkiniz bulunmamaktadır!', 'danger')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

# ============== PERSONEL PANELİ ROUTE'LARI ==============

@leave_requests.route('/employee')
@login_required
@employee_required
def employee_panel():
    """Personel izin talepleri paneli"""
    try:
        # Debug bilgileri
        logger.info(f"Employee panel erişimi - User: {current_user.email}, Role ID: {current_user.role_id}, User ID: {current_user.user_id}")
        
        # Kullanıcının izin taleplerini al
        requests = db_session.query(LeaveRequest)\
            .filter(LeaveRequest.user_id == current_user.user_id)\
            .filter(LeaveRequest.deleted_at.is_(None))\
            .order_by(desc(LeaveRequest.request_date))\
            .all()
        
        logger.info(f"Kullanıcı için {len(requests)} izin talebi bulundu")
        
        return render_template('leave_requests/employee_panel.html', requests=requests)
    
    except Exception as e:
        logger.error(f"Personel paneli hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return render_template('leave_requests/employee_panel.html', requests=[])
    finally:
        db_session.remove()

@leave_requests.route('/employee/create', methods=['GET', 'POST'])
@login_required
@employee_required
def create_request():
    """Yeni izin talebi oluştur"""
    if request.method == 'POST':
        try:
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')
            reason = request.form.get('reason')
            leave_type = request.form.get('leave_type', 'Yıllık İzin')
            
            # Form verilerini kontrol et
            if not start_date or not end_date or not reason:
                return jsonify({'success': False, 'message': 'Lütfen tüm alanları doldurunuz.'})
            
            # Tarih kontrolü
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            end_dt = datetime.strptime(end_date, '%Y-%m-%d')
            
            if start_dt > end_dt:
                return jsonify({'success': False, 'message': 'Başlangıç tarihi bitiş tarihinden sonra olamaz!'})
            
            if start_dt.date() < datetime.now().date():
                return jsonify({'success': False, 'message': 'Geçmiş tarihler için izin talebi oluşturamazsınız!'})
            
            # Gün sayısını hesapla
            days_count = (end_dt - start_dt).days + 1
            
            # Yeni talep oluştur
            new_request = LeaveRequest(
                user_id=current_user.user_id,
                start_date=start_dt,
                end_date=end_dt,
                reason=reason,
                leave_type=leave_type,
                days_count=days_count,
                status='bekleniyor'
            )
            
            db_session.add(new_request)
            db_session.commit()
            
            logger.info(f"Yeni izin talebi oluşturuldu - User: {current_user.user_id}, Tarih: {start_date} - {end_date}")
            
            return jsonify({
                'success': True, 
                'message': f'İzin talebiniz başarıyla oluşturuldu. ({days_count} gün)'
            })
            
        except Exception as e:
            db_session.rollback()
            logger.error(f"İzin talebi oluşturma hatası: {str(e)}")
            return jsonify({'success': False, 'message': f'Bir hata oluştu: {str(e)}'})
        finally:
            db_session.remove()
    
    return render_template('leave_requests/create_request.html')

@leave_requests.route('/employee/cancel/<int:request_id>', methods=['POST'])
@login_required
@employee_required
def cancel_request(request_id):
    """İzin talebini iptal et (sadece bekleniyor durumunda)"""
    try:
        leave_request = db_session.query(LeaveRequest)\
            .filter(LeaveRequest.id == request_id)\
            .filter(LeaveRequest.user_id == current_user.user_id)\
            .filter(LeaveRequest.status == 'bekleniyor')\
            .first()
        
        if not leave_request:
            return jsonify({'success': False, 'message': 'İzin talebi bulunamadı veya iptal edilemez!'})
        
        leave_request.deleted_at = datetime.now()
        db_session.commit()
        
        logger.info(f"İzin talebi iptal edildi - ID: {request_id}, User: {current_user.user_id}")
        
        return jsonify({'success': True, 'message': 'İzin talebiniz iptal edildi.'})
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"İzin talebi iptal hatası: {str(e)}")
        return jsonify({'success': False, 'message': f'Bir hata oluştu: {str(e)}'})
    finally:
        db_session.remove()

@leave_requests.route('/employee/details/<int:request_id>')
@login_required
@employee_required
def employee_request_details(request_id):
    """Personel için izin talebi detayları"""
    try:
        leave_request = db_session.query(LeaveRequest)\
            .filter(LeaveRequest.id == request_id)\
            .filter(LeaveRequest.user_id == current_user.user_id)\
            .first()
        
        if not leave_request:
            return '<p class="text-danger">İzin talebi bulunamadı!</p>'
        
        # Detay HTML'i döndür
        detail_html = f"""
        <div class="row">
            <div class="col-md-6">
                <strong>İzin Türü:</strong><br>
                <span class="text-muted">{leave_request.leave_type}</span>
            </div>
            <div class="col-md-6">
                <strong>Durum:</strong><br>
                <span class="badge bg-{leave_request.status_color}">{leave_request.status_display}</span>
            </div>
        </div>
        <hr>
        <div class="row">
            <div class="col-md-4">
                <strong>Başlangıç Tarihi:</strong><br>
                <span class="text-muted">{leave_request.start_date.strftime('%d.%m.%Y')}</span>
            </div>
            <div class="col-md-4">
                <strong>Bitiş Tarihi:</strong><br>
                <span class="text-muted">{leave_request.end_date.strftime('%d.%m.%Y')}</span>
            </div>
            <div class="col-md-4">
                <strong>Gün Sayısı:</strong><br>
                <span class="text-muted">{leave_request.days_count or leave_request.calculate_days()} gün</span>
            </div>
        </div>
        <hr>
        <div class="row">
            <div class="col-12">
                <strong>İzin Sebebi:</strong><br>
                <p class="text-muted mt-2">{leave_request.reason}</p>
            </div>
        </div>
        <hr>
        <div class="row">
            <div class="col-md-6">
                <strong>Talep Tarihi:</strong><br>
                <span class="text-muted">{leave_request.request_date.strftime('%d.%m.%Y %H:%M')}</span>
            </div>
        """
        
        if leave_request.approved_date:
            detail_html += f"""
            <div class="col-md-6">
                <strong>İşlem Tarihi:</strong><br>
                <span class="text-muted">{leave_request.approved_date.strftime('%d.%m.%Y %H:%M')}</span>
            </div>
            """
        
        detail_html += "</div>"
        
        if leave_request.admin_notes:
            detail_html += f"""
            <hr>
            <div class="row">
                <div class="col-12">
                    <strong>Yönetici Notları:</strong><br>
                    <p class="text-muted mt-2">{leave_request.admin_notes}</p>
                </div>
            </div>
            """
        
        return detail_html
        
    except Exception as e:
        logger.error(f"Employee detay hatası: {str(e)}")
        return '<p class="text-danger">Detaylar yüklenirken hata oluştu!</p>'
    finally:
        db_session.remove()

# ============== ADMİN PANELİ ROUTE'LARI ==============

@leave_requests.route('/admin')
@login_required
@admin_required
def admin_panel():
    """Admin izin yönetimi paneli"""
    try:
        # Tüm izin taleplerini al
        requests = db_session.query(LeaveRequest)\
            .join(User, LeaveRequest.user_id == User.user_id)\
            .filter(LeaveRequest.deleted_at.is_(None))\
            .order_by(desc(LeaveRequest.request_date))\
            .all()
        
        # İstatistikler
        stats = {
            'total': len(requests),
            'pending': len([r for r in requests if r.status == 'bekleniyor']),
            'approved': len([r for r in requests if r.status == 'onaylandı']),
            'rejected': len([r for r in requests if r.status == 'reddedildi'])
        }
        
        return render_template('leave_requests/admin_panel.html', requests=requests, stats=stats)
    
    except Exception as e:
        logger.error(f"Admin paneli hatası: {str(e)}")
        flash('Bir hata oluştu!', 'danger')
        return render_template('leave_requests/admin_panel.html', requests=[], stats={})
    finally:
        db_session.remove()

@leave_requests.route('/admin/approve/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def approve_request(request_id):
    """İzin talebini onayla"""
    try:
        admin_notes = request.form.get('admin_notes', '')
        
        leave_request = db_session.query(LeaveRequest)\
            .filter(LeaveRequest.id == request_id)\
            .filter(LeaveRequest.status == 'bekleniyor')\
            .first()
        
        if not leave_request:
            return jsonify({'success': False, 'message': 'İzin talebi bulunamadı!'})
        
        leave_request.status = 'onaylandı'
        leave_request.approved_by = current_user.user_id
        leave_request.approved_date = datetime.now()
        leave_request.admin_notes = admin_notes
        leave_request.updated_at = datetime.now()
        
        db_session.commit()
        
        logger.info(f"İzin talebi onaylandı - ID: {request_id}, Admin: {current_user.user_id}")
        
        return jsonify({'success': True, 'message': 'İzin talebi onaylandı.'})
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"İzin talebi onaylama hatası: {str(e)}")
        return jsonify({'success': False, 'message': f'Bir hata oluştu: {str(e)}'})
    finally:
        db_session.remove()

@leave_requests.route('/admin/reject/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def reject_request(request_id):
    """İzin talebini reddet"""
    try:
        admin_notes = request.form.get('admin_notes', '')
        
        leave_request = db_session.query(LeaveRequest)\
            .filter(LeaveRequest.id == request_id)\
            .filter(LeaveRequest.status == 'bekleniyor')\
            .first()
        
        if not leave_request:
            return jsonify({'success': False, 'message': 'İzin talebi bulunamadı!'})
        
        leave_request.status = 'reddedildi'
        leave_request.approved_by = current_user.user_id
        leave_request.approved_date = datetime.now()
        leave_request.admin_notes = admin_notes
        leave_request.updated_at = datetime.now()
        
        db_session.commit()
        
        logger.info(f"İzin talebi reddedildi - ID: {request_id}, Admin: {current_user.user_id}")
        
        return jsonify({'success': True, 'message': 'İzin talebi reddedildi.'})
        
    except Exception as e:
        db_session.rollback()
        logger.error(f"İzin talebi reddetme hatası: {str(e)}")
        return jsonify({'success': False, 'message': f'Bir hata oluştu: {str(e)}'})
    finally:
        db_session.remove()

@leave_requests.route('/admin/details/<int:request_id>')
@login_required
@admin_required
def request_details(request_id):
    """İzin talebi detayları - JSON formatında"""
    try:
        leave_request = db_session.query(LeaveRequest)\
            .join(User, LeaveRequest.user_id == User.user_id)\
            .filter(LeaveRequest.id == request_id)\
            .first()
        
        if not leave_request:
            return jsonify({'success': False, 'message': 'İzin talebi bulunamadı!'})
        
        # Onaylayan admin bilgisi
        approver_name = None
        if leave_request.approved_by:
            approver = db_session.query(User)\
                .filter(User.user_id == leave_request.approved_by)\
                .first()
            if approver:
                approver_name = approver.name
        
        # JSON formatında detayları döndür
        data = {
            'id': leave_request.id,
            'user_name': leave_request.user.name,
            'user_email': leave_request.user.email,
            'leave_type': leave_request.leave_type,
            'start_date': leave_request.start_date.strftime('%d.%m.%Y'),
            'end_date': leave_request.end_date.strftime('%d.%m.%Y'),
            'days_count': leave_request.days_count or leave_request.calculate_days(),
            'reason': leave_request.reason,
            'status': leave_request.status,
            'request_date': leave_request.request_date.strftime('%d.%m.%Y %H:%M'),
            'admin_notes': leave_request.admin_notes,
            'approved_by': approver_name,
            'approved_date': leave_request.approved_date.strftime('%d.%m.%Y %H:%M') if leave_request.approved_date else None
        }
        
        return jsonify(data)
    
    except Exception as e:
        logger.error(f"İzin talebi detay hatası: {str(e)}")
        return jsonify({'success': False, 'message': f'Detaylar yüklenirken hata oluştu: {str(e)}'})
    finally:
        db_session.remove() 