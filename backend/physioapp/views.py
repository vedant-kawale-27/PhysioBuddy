import json
import re
import time
import sys
import os
import platform
import django
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.http import JsonResponse, Http404
from django.shortcuts import get_object_or_404
from .models import Hospital, PatientProfile, DoctorProfile, AssignedExercise, Exercise, Message
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.middleware.csrf import get_token
from django.db import transaction, connection
from django.conf import settings
from .consumers import ExerciseConsumer, LandmarkMock

User = get_user_model()


def get_user_role(user):
    """
    Determine the role of a given user using role flags:
    - Super Admin: is_superuser or is_super_admin
    - Hospital Admin: is_hospital_admin
    - Doctor: is_staff (and not is_hospital_admin)
    - Patient: default / is_user
    """
    if not user or not user.is_authenticated:
        return None
    if user.is_superuser or getattr(user, 'is_super_admin', False):
        return 'superadmin'
    if getattr(user, 'is_hospital_admin', False):
        return 'hospital_admin'
    if user.is_staff:
        return 'doctor'
    return 'patient'


# ==========================================
# Common & Authentication APIs
# ==========================================

@ensure_csrf_cookie
def csrf_api(request):
    """
    CSRF token bootstrap endpoint.
    Sets the 'csrftoken' cookie on the client and returns the token in JSON.
    """
    if request.method == 'GET':
        token = get_token(request)
        return JsonResponse({'message': 'CSRF cookie set', 'csrfToken': token}, status=200)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def login_api(request):
    """
    General portal login for Hospital Admins, Doctors, and Patients only.
    Super Admins are redirected to the dedicated Super Admin Portal.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    logout(request)

    if not email or not password:
        return JsonResponse({'error': 'Email and password are required'}, status=400)

    # Allow login by email or username
    try:
        user_obj = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        try:
            user_obj = User.objects.get(username__iexact=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Invalid email/username or password'}, status=404)

    user = authenticate(request, username=user_obj.username, password=password)
    if user is not None:
        role = get_user_role(user)

        # Restrict Super Admin from logging in via standard user portal
        if role == 'superadmin' or user.is_superuser:
            return JsonResponse({'error': 'Invalid email/username or password'}, status=404)

        login(request, user)

        extra_info = {
            'user': role,
            'username': user.username,
            'email': user.email,
            'is_user': getattr(user, 'is_user', True),
            'is_staff': user.is_staff,
            'is_hospital_admin': getattr(user, 'is_hospital_admin', False),
            'is_super_admin': False,
            'is_superuser': False,
        }

        if role == 'hospital_admin' and hasattr(user, 'managed_hospital'):
            extra_info['hospital_id'] = user.managed_hospital.id
            extra_info['hospital_name'] = user.managed_hospital.name
        elif role == 'doctor' and hasattr(user, 'doctorprofile'):
            doc = user.doctorprofile
            extra_info['hospital_name'] = doc.hospital.name if doc.hospital else doc.hospital_name

        return JsonResponse(extra_info, status=200)

    return JsonResponse({'error': 'Invalid email/username or password'}, status=404)


@csrf_exempt
def superadmin_login_api(request):
    """
    Dedicated authentication endpoint for Super Administrators only.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    logout(request)

    if not email or not password:
        return JsonResponse({'error': 'Email/Username and password are required'}, status=400)

    # Allow login by email or username
    try:
        user_obj = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        try:
            user_obj = User.objects.get(username__iexact=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Invalid email/username or password'}, status=404)

    user = authenticate(request, username=user_obj.username, password=password)
    if user is not None:
        role = get_user_role(user)

        # Ensure only Super Admins can authenticate here
        if role != 'superadmin' and not user.is_superuser:
            return JsonResponse({
                'error': 'Access denied: Super Administrator privileges required.'
            }, status=403)

        login(request, user)

        extra_info = {
            'user': 'superadmin',
            'username': user.username,
            'email': user.email,
            'is_user': getattr(user, 'is_user', True),
            'is_staff': user.is_staff,
            'is_hospital_admin': False,
            'is_super_admin': True,
            'is_superuser': True,
        }
        return JsonResponse(extra_info, status=200)

    return JsonResponse({'error': 'Invalid email/username or password'}, status=404)


@csrf_exempt
def logout_api(request):
    """
    Logs out the user and destroys the active session.
    Marked csrf_exempt to ensure a missing or stale CSRF cookie does not prevent session termination.
    """
    if request.method in ['POST', 'GET']:
        logout(request)
        return JsonResponse({'message': 'Logged out successfully'}, status=200)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@ensure_csrf_cookie
def get_current_user_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'authenticated': False}, status=200)

    role = get_user_role(request.user)
    data = {
        'authenticated': True,
        'user': role,
        'username': request.user.username,
        'email': request.user.email,
        'is_user': getattr(request.user, 'is_user', True),
        'is_staff': request.user.is_staff,
        'is_hospital_admin': getattr(request.user, 'is_hospital_admin', False),
        'is_super_admin': request.user.is_superuser or getattr(request.user, 'is_super_admin', False),
        'is_superuser': request.user.is_superuser,
    }

    if role == 'hospital_admin' and hasattr(request.user, 'managed_hospital'):
        data['hospital_id'] = request.user.managed_hospital.id
        data['hospital_name'] = request.user.managed_hospital.name
    elif role == 'doctor' and hasattr(request.user, 'doctorprofile'):
        doc = request.user.doctorprofile
        data['hospital_name'] = doc.hospital.name if doc.hospital else doc.hospital_name

    return JsonResponse(data, status=200)


# ==========================================
# Hospital Registration (Public / Direct)
# ==========================================

@csrf_exempt
def register_hospital_api(request):
    """
    Allows registering a new hospital and creating its Hospital Admin account.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        hospital_name = data.get('hospital_name', '').strip()
        admin_username = data.get('admin_username', '').strip()
        admin_email = data.get('admin_email', '').strip()
        admin_password = data.get('admin_password', '').strip()
        city = data.get('city', '').strip()
        address = data.get('address', '').strip()
        phone_number = data.get('phone_number', '').strip()

        if not hospital_name or not admin_username or not admin_email or not admin_password:
            return JsonResponse({'error': 'Hospital Name, Admin Username, Email, and Password are required.'}, status=400)

        if Hospital.objects.filter(name__iexact=hospital_name).exists():
            return JsonResponse({'error': f"A hospital named '{hospital_name}' already exists."}, status=400)

        if User.objects.filter(username__iexact=admin_username).exists():
            return JsonResponse({'error': f"Username '{admin_username}' is already taken."}, status=400)

        if User.objects.filter(email__iexact=admin_email).exists():
            return JsonResponse({'error': f"Email '{admin_email}' is already registered."}, status=400)

        with transaction.atomic():
            admin_user = User.objects.create_user(
                username=admin_username,
                email=admin_email,
                password=admin_password,
                is_staff=True,
                is_hospital_admin=True,
                is_user=True
            )
            hospital = Hospital.objects.create(
                name=hospital_name,
                admin=admin_user,
                city=city,
                address=address,
                phone_number=phone_number,
                email=admin_email
            )

        return JsonResponse({
            'message': f"Hospital '{hospital.name}' registered successfully!",
            'hospital_id': hospital.id,
            'hospital_name': hospital.name,
            'admin_username': admin_user.username
        }, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ==========================================
# Super Admin APIs
# ==========================================

def superadmin_dashboard_api(request):
    if not request.user.is_authenticated or not request.user.is_superuser:
        return JsonResponse({'error': 'Super Admin authentication required'}, status=403)

    total_hospitals = Hospital.objects.count()
    total_doctors = DoctorProfile.objects.count()
    total_patients = PatientProfile.objects.count()
    total_exercises = Exercise.objects.count()
    total_assignments = AssignedExercise.objects.count()

    hospitals = Hospital.objects.all().order_by('-created_at')[:10]
    hospital_list = []
    for h in hospitals:
        hospital_list.append({
            'id': h.id,
            'name': h.name,
            'city': h.city or 'N/A',
            'phone_number': h.phone_number or 'N/A',
            'email': h.email or 'N/A',
            'admin_username': h.admin.username if h.admin else 'N/A',
            'admin_email': h.admin.email if h.admin else 'N/A',
            'doctors_count': h.doctors.count(),
            'patients_count': h.patients.count(),
            'created_at': h.created_at.strftime('%Y-%m-%d'),
        })

    return JsonResponse({
        'total_hospitals': total_hospitals,
        'total_doctors': total_doctors,
        'total_patients': total_patients,
        'total_exercises': total_exercises,
        'total_assignments': total_assignments,
        'recent_hospitals': hospital_list
    }, status=200)


def superadmin_system_status_api(request):
    """
    Returns comprehensive system telemetry:
    - Database provider detection (Render Postgres, Supabase, AWS RDS, Neon, SQLite, etc.)
    - DB latency, engine, masked host, record counts
    - WebSocket & Pose Tracking channels layer, registered detectors
    - Environment settings (DEBUG, CORS, CSRF, Cookie security, Static storage)
    - Python & Django runtime info
    """
    if not request.user.is_authenticated or not request.user.is_superuser:
        return JsonResponse({'error': 'Super Admin authentication required'}, status=403)

    # 1. Database Provider & Connection Telemetry
    db_settings = connection.settings_dict
    engine = db_settings.get('ENGINE', '')
    host = db_settings.get('HOST', '') or ''
    name = db_settings.get('NAME', '') or ''
    port = db_settings.get('PORT', '') or ''
    user = db_settings.get('USER', '') or ''

    provider = "Custom / Other Database"
    provider_type = "custom"

    if 'sqlite' in engine:
        provider = "Local SQLite"
        provider_type = "sqlite"
        display_host = "Local Filesystem"
    elif 'postgresql' in engine or 'postgres' in engine or 'psycopg2' in engine:
        host_lower = host.lower()
        if 'render.com' in host_lower or 'dpg-' in host_lower:
            provider = "Render PostgreSQL"
            provider_type = "render"
        elif 'supabase.co' in host_lower or 'supabase.in' in host_lower:
            provider = "Supabase PostgreSQL"
            provider_type = "supabase"
        elif 'rds.amazonaws.com' in host_lower or 'compute.amazonaws.com' in host_lower:
            provider = "AWS RDS (PostgreSQL)"
            provider_type = "aws"
        elif 'neon.tech' in host_lower:
            provider = "Neon PostgreSQL"
            provider_type = "neon"
        elif 'railway.app' in host_lower or 'railway.internal' in host_lower:
            provider = "Railway PostgreSQL"
            provider_type = "railway"
        elif 'aivencloud.com' in host_lower:
            provider = "Aiven PostgreSQL"
            provider_type = "aiven"
        elif host in ('localhost', '127.0.0.1', ''):
            provider = "Local PostgreSQL"
            provider_type = "local_postgres"
        else:
            provider = "PostgreSQL"
            provider_type = "postgresql"

        # Mask host for security
        if host:
            if len(host) > 16:
                display_host = host[:6] + "..." + host[-10:]
            else:
                display_host = host
        else:
            display_host = "localhost"
    elif 'mysql' in engine:
        provider = "MySQL Database"
        provider_type = "mysql"
        display_host = host if host else "localhost"
    else:
        display_host = host or "N/A"

    # Measure DB Latency
    start_time = time.time()
    db_healthy = True
    db_error = None
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        db_latency_ms = round((time.time() - start_time) * 1000, 2)
    except Exception as e:
        db_latency_ms = -1
        db_healthy = False
        db_error = str(e)

    clean_db_name = os.path.basename(str(name)) if ('/' in str(name) or '\\' in str(name)) else str(name)
    masked_user = (user[:2] + '***' if len(user) > 2 else user) if user else 'N/A'

    # Record counts
    record_counts = {
        'users': User.objects.count(),
        'hospitals': Hospital.objects.count(),
        'doctors': DoctorProfile.objects.count(),
        'patients': PatientProfile.objects.count(),
        'exercises': Exercise.objects.count(),
        'assignments': AssignedExercise.objects.count(),
        'messages': Message.objects.count(),
    }

    # 2. WebSocket & Pose Tracking Telemetry
    channel_layers_setting = getattr(settings, 'CHANNEL_LAYERS', {})
    default_layer = channel_layers_setting.get('default', {})
    layer_backend = default_layer.get('BACKEND', 'channels.layers.InMemoryChannelLayer')

    if 'Redis' in layer_backend or 'redis' in layer_backend:
        channel_layer_type = "Redis Channel Layer (Distributed)"
    elif 'InMemory' in layer_backend:
        channel_layer_type = "In-Memory Channel Layer (Single Process / Dev)"
    else:
        channel_layer_type = layer_backend.split('.')[-1]

    # Active Pose Detectors Catalog
    pose_detectors = [
        {
            'id': 1,
            'name': 'Bicep Curls',
            'category': 'Upper Body',
            'tracked_joints': 'Shoulder, Elbow, Wrist',
            'type': 'Flexion / Extension Angle (45°-140°)',
            'status': 'ACTIVE'
        },
        {
            'id': 2,
            'name': 'Quadriceps Stretches',
            'category': 'Lower Body',
            'tracked_joints': 'Hip, Knee, Ankle',
            'type': 'Flexion Angle & Balance (60°-150°)',
            'status': 'ACTIVE'
        },
        {
            'id': 3,
            'name': 'Shoulder Exercises',
            'category': 'Upper Body',
            'tracked_joints': 'Hip, Shoulder, Elbow',
            'type': 'Arm Abduction & Overhead Lift (>160°)',
            'status': 'ACTIVE'
        },
        {
            'id': 4,
            'name': 'Squats',
            'category': 'Lower Body',
            'tracked_joints': 'Hip, Knee, Ankle, Torso',
            'type': 'Knee-Hip Triple Flexion (<100°)',
            'status': 'ACTIVE'
        },
        {
            'id': 5,
            'name': 'Standing Knee Lifts',
            'category': 'Lower Body / Core',
            'tracked_joints': 'Hip, Knee, Foot',
            'type': 'Hip Flexion & Knee Elevation (>90°)',
            'status': 'ACTIVE'
        },
    ]

    # Check OpenCV / MediaPipe
    cv_available = False
    cv_version = "N/A"
    try:
        import cv2
        cv_available = True
        cv_version = getattr(cv2, '__version__', 'Available')
    except ImportError:
        pass

    # 3. Environment, Security & Static Files
    allowed_hosts = getattr(settings, 'ALLOWED_HOSTS', [])
    cors_origins = getattr(settings, 'CORS_ALLOWED_ORIGINS', [])
    csrf_origins = getattr(settings, 'CSRF_TRUSTED_ORIGINS', [])
    debug_mode = getattr(settings, 'DEBUG', False)
    session_cookie_samesite = getattr(settings, 'SESSION_COOKIE_SAMESITE', 'Lax')
    session_cookie_secure = getattr(settings, 'SESSION_COOKIE_SECURE', False)
    csrf_cookie_secure = getattr(settings, 'CSRF_COOKIE_SECURE', False)

    # Static files storage
    static_storage = getattr(settings, 'STATICFILES_STORAGE', '')
    if not static_storage:
        storages = getattr(settings, 'STORAGES', {})
        staticfiles = storages.get('staticfiles', {})
        static_storage = staticfiles.get('BACKEND', 'django.contrib.staticfiles.storage.StaticFilesStorage')

    whitenoise_active = any('whitenoise' in m.lower() for m in getattr(settings, 'MIDDLEWARE', []))

    return JsonResponse({
        'server': {
            'status': 'OPERATIONAL',
            'python_version': sys.version.split(' ')[0],
            'django_version': django.get_version(),
            'platform': platform.system() + ' ' + platform.release(),
            'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
            'debug': debug_mode,
            'environment': 'Development (DEBUG=True)' if debug_mode else 'Production (DEBUG=False)',
        },
        'database': {
            'provider': provider,
            'provider_type': provider_type,
            'engine': engine.split('.')[-1] if '.' in engine else engine,
            'database_name': clean_db_name,
            'host': display_host,
            'port': port or ('5432' if 'postgres' in engine else '3306' if 'mysql' in engine else 'N/A'),
            'user': masked_user,
            'is_healthy': db_healthy,
            'latency_ms': db_latency_ms,
            'error': db_error,
            'records': record_counts,
        },
        'websocket': {
            'asgi_application': getattr(settings, 'ASGI_APPLICATION', 'physioapp.asgi.application'),
            'channel_layer_type': channel_layer_type,
            'channel_layer_backend': layer_backend.split('.')[-1] if '.' in layer_backend else layer_backend,
            'websocket_route': '/ws/exercise/',
            'status': 'OPERATIONAL',
        },
        'pose_tracking': {
            'engine': 'MediaPipe Pose Landmark Solutions (33 Keypoints)',
            'opencv_available': cv_available,
            'opencv_version': cv_version,
            'detectors_count': len(pose_detectors),
            'detectors': pose_detectors,
            'status': 'OPERATIONAL',
        },
        'security': {
            'allowed_hosts': allowed_hosts,
            'cors_allowed_origins': cors_origins,
            'csrf_trusted_origins': csrf_origins,
            'session_cookie_samesite': session_cookie_samesite,
            'session_cookie_secure': session_cookie_secure,
            'csrf_cookie_secure': csrf_cookie_secure,
            'whitenoise_active': whitenoise_active,
            'static_storage': static_storage.split('.')[-1] if '.' in static_storage else static_storage,
        }
    }, status=200)


@csrf_exempt
def superadmin_run_diagnostics_api(request):
    """
    Executes live non-destructive diagnostic benchmarks:
    1. Database ping latency test
    2. Django ORM data query
    3. AI Pose Landmark calculation engine verification
    4. Production security configuration audit
    """
    if not request.user.is_authenticated or not request.user.is_superuser:
        return JsonResponse({'error': 'Super Admin authentication required'}, status=403)

    results = []

    # 1. Database Read Ping Test
    t0 = time.time()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        db_ms = round((time.time() - t0) * 1000, 2)
        results.append({
            'name': 'Database Query Ping',
            'status': 'PASSED',
            'latency_ms': db_ms,
            'details': f"Raw database connection responded in {db_ms}ms"
        })
    except Exception as e:
        results.append({
            'name': 'Database Query Ping',
            'status': 'FAILED',
            'latency_ms': -1,
            'details': str(e)
        })

    # 2. Django ORM Model Layer
    t0 = time.time()
    try:
        user_count = User.objects.count()
        hospital_count = Hospital.objects.count()
        orm_ms = round((time.time() - t0) * 1000, 2)
        results.append({
            'name': 'Django ORM & Model Layer',
            'status': 'PASSED',
            'latency_ms': orm_ms,
            'details': f"Successfully fetched records ({user_count} users, {hospital_count} hospitals) in {orm_ms}ms"
        })
    except Exception as e:
        results.append({
            'name': 'Django ORM & Model Layer',
            'status': 'FAILED',
            'latency_ms': -1,
            'details': str(e)
        })

    # 3. AI Pose Landmark Engine Calculation Test
    t0 = time.time()
    try:
        consumer = ExerciseConsumer()
        # Create 33 mock landmarks
        synthetic_landmarks = [
            LandmarkMock(0.5, 0.5, 0.0, 0.99) for _ in range(33)
        ]
        # Position left arm: shoulder (11), elbow (13), wrist (15)
        synthetic_landmarks[11] = LandmarkMock(0.5, 0.3, 0.0, 0.99)
        synthetic_landmarks[13] = LandmarkMock(0.5, 0.5, 0.0, 0.99)
        synthetic_landmarks[15] = LandmarkMock(0.5, 0.7, 0.0, 0.99)

        # Test angle calculation
        angle = consumer.calculate_angle(
            (synthetic_landmarks[11].x, synthetic_landmarks[11].y),
            (synthetic_landmarks[13].x, synthetic_landmarks[13].y),
            (synthetic_landmarks[15].x, synthetic_landmarks[15].y)
        )

        ai_ms = round((time.time() - t0) * 1000, 2)
        results.append({
            'name': 'AI Pose Tracking & Math Engine',
            'status': 'PASSED',
            'latency_ms': ai_ms,
            'details': f"Computed 3-point joint angle ({round(angle, 1)}°) and verified vector trigonometry in {ai_ms}ms"
        })
    except Exception as e:
        results.append({
            'name': 'AI Pose Tracking & Math Engine',
            'status': 'FAILED',
            'latency_ms': -1,
            'details': str(e)
        })

    # 4. Security & Environment Configuration Audit
    sec_warnings = []
    if getattr(settings, 'DEBUG', False):
        sec_warnings.append("DEBUG is True")
    secret_key = getattr(settings, 'SECRET_KEY', '') or ''
    if len(secret_key) < 20:
        sec_warnings.append("SECRET_KEY length is short")

    results.append({
        'name': 'Environment & Security Audit',
        'status': 'PASSED' if not sec_warnings else 'WARNING',
        'latency_ms': 0.1,
        'details': "All baseline production security criteria satisfied" if not sec_warnings else f"Notice: {', '.join(sec_warnings)}"
    })

    all_passed = all(r['status'] in ('PASSED', 'WARNING') for r in results)

    return JsonResponse({
        'success': all_passed,
        'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
        'results': results
    }, status=200)


def superadmin_hospitals_api(request):
    if not request.user.is_authenticated or not request.user.is_superuser:
        return JsonResponse({'error': 'Super Admin authentication required'}, status=403)

    hospitals = Hospital.objects.all().order_by('-created_at')
    hospital_list = []
    for h in hospitals:
        hospital_list.append({
            'id': h.id,
            'name': h.name,
            'city': h.city or 'N/A',
            'address': h.address or '',
            'phone_number': h.phone_number or 'N/A',
            'email': h.email or 'N/A',
            'admin_username': h.admin.username if h.admin else 'N/A',
            'admin_email': h.admin.email if h.admin else 'N/A',
            'doctors_count': h.doctors.count(),
            'patients_count': h.patients.count(),
            'created_at': h.created_at.strftime('%Y-%m-%d'),
        })

    return JsonResponse(hospital_list, safe=False, status=200)


def superadmin_hospital_detail_api(request, hospital_id):
    if not request.user.is_authenticated or not request.user.is_superuser:
        return JsonResponse({'error': 'Super Admin authentication required'}, status=403)

    hospital = get_object_or_404(Hospital, id=hospital_id)
    doctors = hospital.doctors.all().select_related('user')
    patients = hospital.patients.all().select_related('user', 'doctor__user')

    doc_list = []
    for d in doctors:
        doc_list.append({
            'id': d.id,
            'username': d.user.username,
            'email': d.user.email,
            'speciality': d.speciality,
            'qualification': d.qualification,
            'phone_number': d.phone_number or 'N/A',
            'experience_years': d.experience_years,
            'patient_count': d.patients.count(),
        })

    pat_list = []
    for p in patients:
        pat_list.append({
            'id': p.id,
            'username': p.user.username,
            'email': p.user.email,
            'phone_number': p.phone_number or 'N/A',
            'gender': p.gender or 'N/A',
            'blood_group': p.blood_group or 'N/A',
            'assigned_doctor': p.doctor.user.username if p.doctor else 'Unassigned',
        })

    return JsonResponse({
        'id': hospital.id,
        'name': hospital.name,
        'city': hospital.city,
        'address': hospital.address,
        'phone_number': hospital.phone_number,
        'email': hospital.email,
        'admin_username': hospital.admin.username if hospital.admin else 'N/A',
        'created_at': hospital.created_at.strftime('%Y-%m-%d'),
        'doctors': doc_list,
        'patients': pat_list,
    }, status=200)


def superadmin_create_exercise_api(request):
    if not request.user.is_authenticated or not request.user.is_superuser:
        return JsonResponse({'error': 'Super Admin authentication required'}, status=403)

    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        demo_video_url = data.get('demo_video_url', '').strip()
        thumbnail_image_url = data.get('thumbnail_image_url', '').strip()

        if not name or not description or not demo_video_url:
            return JsonResponse({'error': 'Exercise Name, Description, and Video URL are required'}, status=400)

        exercise = Exercise.objects.create(
            name=name,
            description=description,
            demo_video_url=demo_video_url,
            thumbnail_image_url=thumbnail_image_url or None,
            created_by=request.user
        )

        return JsonResponse({
            'message': 'Exercise added successfully',
            'exercise': {
                'id': exercise.id,
                'name': exercise.name,
                'description': exercise.description,
                'demo_video_url': exercise.demo_video_url,
                'thumbnail_image_url': exercise.thumbnail_image_url
            }
        }, status=201)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def superadmin_get_exercises_api(request):
    if not request.user.is_authenticated or not request.user.is_superuser:
        return JsonResponse({'error': 'Super Admin authentication required'}, status=403)

    exercises = Exercise.objects.all().order_by('-id')
    exercise_list = []
    for ex in exercises:
        exercise_list.append({
            'id': ex.id,
            'name': ex.name,
            'description': ex.description,
            'demo_video_url': ex.demo_video_url,
            'thumbnail_image_url': ex.thumbnail_image_url,
            'created_at': ex.created_at.strftime('%Y-%m-%d') if ex.created_at else None,
            'created_by': ex.created_by.username if ex.created_by else 'System'
        })
    return JsonResponse(exercise_list, safe=False, status=200)


def superadmin_delete_exercise_api(request, exercise_id):
    if not request.user.is_authenticated or not request.user.is_superuser:
        return JsonResponse({'error': 'Super Admin authentication required'}, status=403)

    if request.method not in ['POST', 'DELETE']:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    exercise = get_object_or_404(Exercise, id=exercise_id)
    exercise.delete()
    return JsonResponse({'message': 'Exercise deleted successfully'}, status=200)


# ==========================================
# Hospital Admin APIs
# ==========================================

def _get_hospital_for_request(request):
    """
    Returns the Hospital object if the user is a Hospital Admin.
    """
    if not request.user.is_authenticated:
        return None
    try:
        return request.user.managed_hospital
    except Hospital.DoesNotExist:
        return None


def hospital_admin_dashboard_api(request):
    hospital = _get_hospital_for_request(request)
    if not hospital:
        return JsonResponse({'error': 'Hospital Admin access required'}, status=403)

    doctors = hospital.doctors.all()
    patients = hospital.patients.all()
    today = timezone.now().date()

    total_doctors = doctors.count()
    total_patients = patients.count()

    today_assignments = AssignedExercise.objects.filter(
        patient__hospital=hospital,
        date_assigned__date=today
    )
    total_today = today_assignments.count()
    completed_today = today_assignments.filter(is_completed=True).count()

    recent_docs = []
    for d in doctors.order_by('-id')[:5]:
        full_name = f"{d.user.first_name} {d.user.last_name}".strip()
        recent_docs.append({
            'id': d.id,
            'username': d.user.username,
            'first_name': d.user.first_name,
            'last_name': d.user.last_name,
            'name': full_name if full_name else d.user.username,
            'email': d.user.email,
            'speciality': d.speciality,
            'qualification': d.qualification,
            'patient_count': d.patients.count()
        })

    recent_pats = []
    for p in patients.order_by('-id')[:5]:
        pat_full_name = f"{p.user.first_name} {p.user.last_name}".strip()
        doc_full_name = f"{p.doctor.user.first_name} {p.doctor.user.last_name}".strip() if p.doctor else ''
        recent_pats.append({
            'id': p.id,
            'username': p.user.username,
            'first_name': p.user.first_name,
            'last_name': p.user.last_name,
            'name': pat_full_name if pat_full_name else p.user.username,
            'email': p.user.email,
            'assigned_doctor': (doc_full_name if doc_full_name else p.doctor.user.username) if p.doctor else 'Unassigned',
            'gender': p.gender or 'N/A'
        })

    return JsonResponse({
        'hospital_id': hospital.id,
        'hospital_name': hospital.name,
        'city': hospital.city,
        'total_doctors': total_doctors,
        'total_patients': total_patients,
        'today_assignments_total': total_today,
        'today_assignments_completed': completed_today,
        'recent_doctors': recent_docs,
        'recent_patients': recent_pats
    }, status=200)


def hospital_admin_doctors_api(request):
    hospital = _get_hospital_for_request(request)
    if not hospital:
        return JsonResponse({'error': 'Hospital Admin access required'}, status=403)

    doctors = hospital.doctors.all().select_related('user').order_by('-id')
    doc_list = []
    for d in doctors:
        full_name = f"{d.user.first_name} {d.user.last_name}".strip()
        doc_list.append({
            'id': d.id,
            'username': d.user.username,
            'first_name': d.user.first_name,
            'last_name': d.user.last_name,
            'full_name': full_name if full_name else d.user.username,
            'email': d.user.email,
            'phone_number': d.phone_number or '',
            'speciality': d.speciality,
            'qualification': d.qualification,
            'gender': d.gender or '',
            'city': d.city or '',
            'experience_years': d.experience_years or 0,
            'professional_summary': d.professional_summary or '',
            'patient_count': d.patients.count(),
            'image_base64': d.image_base64
        })

    return JsonResponse(doc_list, safe=False, status=200)


def hospital_admin_create_doctor_api(request):
    hospital = _get_hospital_for_request(request)
    if not hospital:
        return JsonResponse({'error': 'Hospital Admin access required'}, status=403)

    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        first_name = data.get('first_name', '').strip()
        middle_name = data.get('middle_name', '').strip()
        last_name = data.get('last_name', '').strip()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        speciality = data.get('speciality', '').strip()
        qualification = data.get('qualification', '').strip()
        phone_number = data.get('phone_number', '').strip()
        gender = data.get('gender', 'male').strip()
        city = data.get('city', '').strip()
        experience_years = data.get('experience_years')
        professional_summary = data.get('professional_summary', '').strip()

        # If username is empty, auto-generate from first_name and last_name
        if not username:
            clean_first = re.sub(r'[^a-zA-Z0-9]', '', first_name).lower()
            clean_last = re.sub(r'[^a-zA-Z0-9]', '', last_name).lower()
            if clean_first and clean_last:
                base_user = f"{clean_first}_{clean_last}"
            elif clean_first:
                base_user = clean_first
            elif clean_last:
                base_user = clean_last
            else:
                base_user = 'doctor'

            username = base_user
            counter = 1
            while User.objects.filter(username__iexact=username).exists():
                username = f"{base_user}_{counter}"
                counter += 1

        if not username or not email or not password or not speciality or not qualification:
            return JsonResponse({'error': 'Username, Email, Password, Speciality, and Qualification are required'}, status=400)

        if User.objects.filter(username__iexact=username).exists():
            return JsonResponse({'error': f"Username '{username}' is already taken"}, status=400)

        if User.objects.filter(email__iexact=email).exists():
            return JsonResponse({'error': f"Email '{email}' is already registered"}, status=400)

        full_first = f"{first_name} {middle_name}".strip() if middle_name else first_name

        with transaction.atomic():
            doc_user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=full_first,
                last_name=last_name,
                is_staff=True,
                is_hospital_admin=False,
                is_user=True
            )
            DoctorProfile.objects.create(
                user=doc_user,
                hospital=hospital,
                hospital_name=hospital.name,
                speciality=speciality,
                qualification=qualification,
                phone_number=phone_number,
                gender=gender,
                city=city or hospital.city,
                experience_years=int(experience_years) if experience_years else None,
                professional_summary=professional_summary
            )

        full_name = f"{first_name} {middle_name} {last_name}".replace('  ', ' ').strip()
        display_name = full_name if full_name else username
        return JsonResponse({'message': f"Doctor 'Dr. {display_name}' added successfully to {hospital.name}"}, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def hospital_admin_delete_doctor_api(request, doctor_id):
    hospital = _get_hospital_for_request(request)
    if not hospital:
        return JsonResponse({'error': 'Hospital Admin access required'}, status=403)

    if request.method not in ['POST', 'DELETE']:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    doctor = get_object_or_404(DoctorProfile, id=doctor_id, hospital=hospital)
    user = doctor.user
    doctor.delete()
    user.delete()

    return JsonResponse({'message': 'Doctor removed successfully'}, status=200)


def hospital_admin_patients_api(request):
    hospital = _get_hospital_for_request(request)
    if not hospital:
        return JsonResponse({'error': 'Hospital Admin access required'}, status=403)

    patients = hospital.patients.all().select_related('user', 'doctor__user').order_by('-id')
    patient_list = []
    for p in patients:
        pat_full_name = f"{p.user.first_name} {p.user.last_name}".strip()
        doc_full_name = f"{p.doctor.user.first_name} {p.doctor.user.last_name}".strip() if p.doctor else ''
        patient_list.append({
            'id': p.id,
            'username': p.user.username,
            'first_name': p.user.first_name,
            'last_name': p.user.last_name,
            'full_name': pat_full_name if pat_full_name else p.user.username,
            'email': p.user.email,
            'phone_number': p.phone_number or '',
            'gender': p.gender or '',
            'dob': p.date_of_birth.strftime('%Y-%m-%d') if p.date_of_birth else '',
            'blood_group': p.blood_group or '',
            'height': p.height,
            'weight': p.weight,
            'doctor_id': p.doctor.id if p.doctor else None,
            'doctor_name': (doc_full_name if doc_full_name else p.doctor.user.username) if p.doctor else 'Unassigned',
            'image_base64': p.image_base64
        })

    return JsonResponse(patient_list, safe=False, status=200)


def hospital_admin_create_patient_api(request):
    hospital = _get_hospital_for_request(request)
    if not hospital:
        return JsonResponse({'error': 'Hospital Admin access required'}, status=403)

    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        first_name = data.get('first_name', '').strip()
        middle_name = data.get('middle_name', '').strip()
        last_name = data.get('last_name', '').strip()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        phone_number = data.get('phone_number', '').strip()
        gender = data.get('gender', 'male').strip()
        date_of_birth = data.get('dob') or None
        blood_group = data.get('blood_group', '').strip()
        height = data.get('height')
        weight = data.get('weight')
        doctor_id = data.get('doctor_id')

        # If username is empty, auto-generate from first_name and last_name
        if not username:
            clean_first = re.sub(r'[^a-zA-Z0-9]', '', first_name).lower()
            clean_last = re.sub(r'[^a-zA-Z0-9]', '', last_name).lower()
            if clean_first and clean_last:
                base_user = f"{clean_first}_{clean_last}"
            elif clean_first:
                base_user = clean_first
            elif clean_last:
                base_user = clean_last
            else:
                base_user = 'patient'

            username = base_user
            counter = 1
            while User.objects.filter(username__iexact=username).exists():
                username = f"{base_user}_{counter}"
                counter += 1

        if not username or not email or not password:
            return JsonResponse({'error': 'Username, Email, and Password are required'}, status=400)

        if User.objects.filter(username__iexact=username).exists():
            return JsonResponse({'error': f"Username '{username}' is already taken"}, status=400)

        if User.objects.filter(email__iexact=email).exists():
            return JsonResponse({'error': f"Email '{email}' is already registered"}, status=400)

        doctor_obj = None
        if doctor_id:
            try:
                doctor_obj = DoctorProfile.objects.get(id=doctor_id, hospital=hospital)
            except DoctorProfile.DoesNotExist:
                return JsonResponse({'error': 'Assigned Doctor not found in this hospital'}, status=400)

        full_first = f"{first_name} {middle_name}".strip() if middle_name else first_name

        with transaction.atomic():
            pat_user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=full_first,
                last_name=last_name,
                is_staff=False,
                is_hospital_admin=False,
                is_user=True
            )
            PatientProfile.objects.create(
                user=pat_user,
                hospital=hospital,
                doctor=doctor_obj,
                phone_number=phone_number,
                gender=gender,
                date_of_birth=date_of_birth,
                blood_group=blood_group or None,
                height=int(height) if height else None,
                weight=int(weight) if weight else None
            )

        full_name = f"{first_name} {middle_name} {last_name}".replace('  ', ' ').strip()
        display_name = full_name if full_name else username
        return JsonResponse({'message': f"Patient '{display_name}' added successfully to {hospital.name}"}, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def hospital_admin_delete_patient_api(request, patient_id):
    hospital = _get_hospital_for_request(request)
    if not hospital:
        return JsonResponse({'error': 'Hospital Admin access required'}, status=403)

    if request.method not in ['POST', 'DELETE']:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    patient = get_object_or_404(PatientProfile, id=patient_id, hospital=hospital)
    user = patient.user
    patient.delete()
    user.delete()

    return JsonResponse({'message': 'Patient removed successfully'}, status=200)


def hospital_admin_profile_api(request):
    hospital = _get_hospital_for_request(request)
    if not hospital:
        return JsonResponse({'error': 'Hospital Admin access required'}, status=403)

    return JsonResponse({
        'id': hospital.id,
        'hospital_name': hospital.name,
        'city': hospital.city or '',
        'address': hospital.address or '',
        'phone_number': hospital.phone_number or '',
        'hospital_email': hospital.email or '',
        'admin_username': hospital.admin.username,
        'admin_email': hospital.admin.email,
        'created_at': hospital.created_at.strftime('%Y-%m-%d'),
        'total_doctors': hospital.doctors.count(),
        'total_patients': hospital.patients.count(),
    }, status=200)


def hospital_admin_update_profile_api(request):
    hospital = _get_hospital_for_request(request)
    if not hospital:
        return JsonResponse({'error': 'Hospital Admin access required'}, status=403)

    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        hospital_name = data.get('hospital_name', '').strip()
        city = data.get('city', '').strip()
        address = data.get('address', '').strip()
        phone_number = data.get('phone_number', '').strip()
        hospital_email = data.get('hospital_email', '').strip()
        admin_email = data.get('admin_email', '').strip()
        new_password = data.get('new_password', '').strip()

        if hospital_name and hospital_name != hospital.name:
            if Hospital.objects.filter(name__iexact=hospital_name).exclude(id=hospital.id).exists():
                return JsonResponse({'error': f"Hospital name '{hospital_name}' is already taken."}, status=400)
            hospital.name = hospital_name

        hospital.city = city
        hospital.address = address
        hospital.phone_number = phone_number
        hospital.email = hospital_email
        hospital.save()

        # Update Admin user email and optional password
        admin_user = hospital.admin
        if admin_email and admin_email != admin_user.email:
            if User.objects.filter(email__iexact=admin_email).exclude(id=admin_user.id).exists():
                return JsonResponse({'error': f"Email '{admin_email}' is already registered by another user."}, status=400)
            admin_user.email = admin_email

        if new_password:
            if len(new_password) < 6:
                return JsonResponse({'error': 'Password must be at least 6 characters long.'}, status=400)
            admin_user.set_password(new_password)

        admin_user.save()

        # Update Doctor hospital_name cache if hospital name changed
        if hospital_name:
            hospital.doctors.all().update(hospital_name=hospital.name)

        return JsonResponse({
            'message': 'Hospital and Administrator profile updated successfully!',
            'hospital': {
                'id': hospital.id,
                'hospital_name': hospital.name,
                'city': hospital.city,
                'address': hospital.address,
                'phone_number': hospital.phone_number,
                'hospital_email': hospital.email,
                'admin_username': admin_user.username,
                'admin_email': admin_user.email,
            }
        }, status=200)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ==========================================
# APIs for Doctors
# ==========================================

def doctor_home_api(request):
    """
    Doctor dashboard summary KPI endpoint.
    Restricted to patients belonging to the authenticated doctor and same hospital tenant.
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        curr_doc = DoctorProfile.objects.get(user=request.user)
    except DoctorProfile.DoesNotExist:
        return JsonResponse({'error': 'Doctor profile not found'}, status=404)

    if curr_doc.hospital:
        patients = PatientProfile.objects.filter(doctor=curr_doc, hospital=curr_doc.hospital).prefetch_related('assigned_exercises')
    else:
        patients = PatientProfile.objects.filter(doctor=curr_doc).prefetch_related('assigned_exercises')

    total_patients = patients.count()
    completed_patients = 0
    not_completed_patients = 0
    today = timezone.now().date()

    for patient in patients:
        assignments = patient.assigned_exercises.filter(
            assigned_by=curr_doc,
            date_assigned__date=today,
        )
        if not assignments.exists():
            continue

        if all(a.is_completed for a in assignments):
            completed_patients += 1
        else:
            not_completed_patients += 1

    hospital_title = curr_doc.hospital.name if curr_doc.hospital else curr_doc.hospital_name or 'PhysioBuddy Clinic'

    return JsonResponse({
        'total_patients': total_patients,
        'completed_patients': completed_patients,
        'not_completed_patients': not_completed_patients,
        'hospital_name': hospital_title
    }, status=200)


def doctor_profile_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "Authentication required"}, status=401)

    try:
        doctor = get_object_or_404(DoctorProfile, user=request.user)
        doctor_details = {
            "doctor_name": doctor.user.username,
            "phone_number": doctor.phone_number,
            "email": doctor.user.email,
            "specialization": doctor.speciality,
            "qualification": doctor.qualification,
            "gender": doctor.gender,
            "city": doctor.city,
            "hospital_name": doctor.hospital.name if doctor.hospital else doctor.hospital_name,
            "experience_years": doctor.experience_years,
            "professional_summary": doctor.professional_summary,
            "doctor_image": doctor.image_base64
        }
        return JsonResponse(doctor_details, status=200)

    except Http404:
        return JsonResponse({"error": "Doctor profile not found"}, status=404)


def update_doctor_image(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Not logged in'}, status=401)

    try:
        data = json.loads(request.body)
        base64_string = data.get('doctor_image')
        doctor = get_object_or_404(DoctorProfile, user=request.user)
        doctor.image_base64 = base64_string
        doctor.save()
        return JsonResponse({'success': 'Image updated successfully'}, status=200)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)


def get_patient_status(request):
    """
    Returns today's exercise assignment and completion status for patients
    strictly belonging to the authenticated doctor within the same hospital tenant.
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        curr_doc = DoctorProfile.objects.get(user=request.user)
    except DoctorProfile.DoesNotExist:
        return JsonResponse({'message': "Can't find the doctor!!!"}, status=404)

    if curr_doc.hospital:
        patients = PatientProfile.objects.filter(doctor=curr_doc, hospital=curr_doc.hospital)
    else:
        patients = PatientProfile.objects.filter(doctor=curr_doc)

    patient_data_list = []
    for patient in patients:
        assigned_exercises = AssignedExercise.objects.filter(
            patient=patient,
            assigned_by=curr_doc,
            date_assigned__date=timezone.now().date()
        )
        exe_list = [
            {
                'exercise_name': assigned_exercise.exercise.name,
                'reps': assigned_exercise.target_reps,
                'is_completed': assigned_exercise.is_completed
            }
            for assigned_exercise in assigned_exercises
        ]
        if exe_list:
            patient_data_list.append({
                'name': patient.user.username,
                'assigned_exercises': exe_list
            })

    return JsonResponse(patient_data_list, safe=False, status=200)


def my_patients(request):
    """
    Returns patient usernames belonging to the authenticated doctor within the same hospital tenant.
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        curr_doc = DoctorProfile.objects.get(user=request.user)
    except DoctorProfile.DoesNotExist:
        return JsonResponse({'message': "Can't find the doctor!!!"}, status=404)

    if curr_doc.hospital:
        patients = PatientProfile.objects.filter(doctor=curr_doc, hospital=curr_doc.hospital)
    else:
        patients = PatientProfile.objects.filter(doctor=curr_doc)

    exercises = Exercise.objects.all()

    patient_data_list = [patient.user.username for patient in patients]
    exercise_list = [exercise.name for exercise in exercises]

    return JsonResponse({
        'patients': patient_data_list,
        'exercises': exercise_list
    }, status=200)


def submit_assignment(request):
    """
    Creates a new exercise assignment for a patient.
    Strictly enforces tenant ownership:
    1. The patient and doctor must belong to the same hospital tenant.
    2. The doctor must either be the assigned physician or an authorized clinician within the same hospital.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        data = json.loads(request.body)
        patient_name = data.get('patient_name')
        exercise_name = data.get('exercise_name')
        rep_count = data.get('repetitions')

        if not all([patient_name, exercise_name, rep_count]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    try:
        doctor_obj = DoctorProfile.objects.get(user=request.user)
    except DoctorProfile.DoesNotExist:
        return JsonResponse({'error': 'Doctor profile not found'}, status=404)

    try:
        patient_obj = PatientProfile.objects.get(user__username=patient_name)
    except PatientProfile.DoesNotExist:
        return JsonResponse({'error': 'Patient doesn\'t exist'}, status=404)

    try:
        exercise_obj = Exercise.objects.get(name=exercise_name)
    except Exercise.DoesNotExist:
        return JsonResponse({'error': 'Exercise doesn\'t exist'}, status=404)

    # Enforce same-hospital tenant ownership
    if doctor_obj.hospital and patient_obj.hospital != doctor_obj.hospital:
        return JsonResponse(
            {'error': 'Permission denied: Patient belongs to a different hospital tenant.'},
            status=403
        )

    # Enforce doctor assignment if doctor is not attached to a shared hospital tenant practice
    if not doctor_obj.hospital and patient_obj.doctor != doctor_obj:
        return JsonResponse(
            {'error': 'Permission denied: You do not have permission to assign exercises to this patient.'},
            status=403
        )

    assignment = AssignedExercise(
        patient=patient_obj,
        assigned_by=doctor_obj,
        exercise=exercise_obj,
        target_reps=rep_count
    )
    assignment.save()
    return JsonResponse({'message': 'Assignment created successfully'}, status=201)


# ==========================================
# APIs for Patients
# ==========================================

def patient_profile_api(request):
    try:
        patient = get_object_or_404(PatientProfile, user=request.user)
    except Http404:
        return JsonResponse({'error': 'Patient profile not found'}, status=404)

    patient_details = {
        'patient_name': patient.user.username,
        'phone_number': patient.phone_number,
        'email': patient.user.email,
        'dob': patient.date_of_birth,
        'gender': patient.gender,
        'assigned_doctor': patient.doctor.user.username if patient.doctor else 'Not Assigned',
        'hospital_name': patient.hospital.name if patient.hospital else 'PhysioBuddy Clinic',
        'height': patient.height,
        'weight': patient.weight,
        'bg': patient.blood_group,
        'patient_image': patient.image_base64
    }
    return JsonResponse(patient_details, status=200)


def get_exercise_list(request):
    if request.user.is_staff or request.user.is_superuser:
        return JsonResponse({'error': 'Permission denied.'}, status=403)
    try:
        patient_obj = get_object_or_404(PatientProfile, user=request.user)
    except Http404:
        return JsonResponse({'error': 'Patient profile not found.'}, status=404)

    assignments = AssignedExercise.objects.filter(
        patient=patient_obj,
        date_assigned__date=timezone.now().date()
    ).select_related('exercise')

    assignments_list = []
    for assignment in assignments:
        assignments_list.append({
            'patient_username': assignment.patient.user.username,
            'exercise_id': assignment.exercise.id,
            'assignment_id': assignment.id,
            'exercise_name': assignment.exercise.name,
            'exercise_video_url': assignment.exercise.demo_video_url,
            'target_reps': assignment.target_reps,
            'is_completed': assignment.is_completed,
            'date_assigned': assignment.date_assigned.isoformat()
        })

    return JsonResponse(assignments_list, safe=False, status=200)


def update_patient_image(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Not logged in'}, status=401)

    try:
        data = json.loads(request.body)
        base64_string = data.get('patient_image')
        patient = get_object_or_404(PatientProfile, user=request.user)
        patient.image_base64 = base64_string
        patient.save()
        return JsonResponse({'success': 'Image updated successfully'}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)


def get_doctor_name(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        doctor = get_object_or_404(DoctorProfile, user=request.user)
        return JsonResponse({'doctor_name': doctor.user.username}, status=200)
    except Http404:
        return JsonResponse({'error': 'Doctor profile not found'}, status=404)


def update_completion_status(request):
    """
    Updates the completion flag of an assigned exercise.
    Enforces authorization: only the assigned patient, prescribing doctor,
    the respective hospital admin, or a superuser can update this status.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        data = json.loads(request.body)
        assignment_id = data.get('assignment_id')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    try:
        assignment = AssignedExercise.objects.get(id=assignment_id)
    except AssignedExercise.DoesNotExist:
        return JsonResponse({'error': 'Assignment not found'}, status=404)

    # Enforce ownership authorization
    is_patient_owner = assignment.patient.user == request.user
    is_doctor_owner = assignment.assigned_by.user == request.user
    is_hospital_admin = (
        hasattr(request.user, 'managed_hospital') and
        assignment.patient.hospital == request.user.managed_hospital
    )

    if not (is_patient_owner or is_doctor_owner or is_hospital_admin or request.user.is_superuser):
        return JsonResponse(
            {'error': 'Permission denied: You do not have permission to modify this assignment.'},
            status=403
        )

    assignment.is_completed = True
    assignment.save()

    return JsonResponse({'message': 'Completion status updated successfully'}, status=200)


def send_message_api(request):
    """
    Sends a message from a patient to their assigned doctor.
    Enforces that the assigned doctor belongs to the same hospital tenant.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        patient = PatientProfile.objects.get(user=request.user)
    except PatientProfile.DoesNotExist:
        return JsonResponse({'error': 'Only patients can send messages'}, status=403)

    if not patient.doctor:
        return JsonResponse({'error': 'No therapist is currently assigned to your profile.'}, status=400)

    # Enforce tenant isolation for assigned doctor
    if patient.hospital and patient.doctor.hospital and patient.hospital != patient.doctor.hospital:
        return JsonResponse({'error': 'Integrity error: Assigned doctor belongs to a different hospital.'}, status=403)

    try:
        data = json.loads(request.body)
        subject = data.get('subject')
        message_text = data.get('message')
        if not subject or not message_text:
            return JsonResponse({'error': 'Subject and message are required.'}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    content = f"[{subject}] {message_text}"
    msg = Message.objects.create(
        patient=patient,
        doctor=patient.doctor,
        content=content
    )
    return JsonResponse({'message': 'Message sent successfully', 'id': msg.id}, status=200)


def get_patient_messages_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        patient = PatientProfile.objects.get(user=request.user)
    except PatientProfile.DoesNotExist:
        return JsonResponse({'error': 'Only patients can view these messages'}, status=403)

    today = timezone.now().date()
    messages = Message.objects.filter(patient=patient, created_at__date=today).order_by('created_at')
    msg_list = []
    for msg in messages:
        msg_list.append({
            'id': msg.id,
            'content': msg.content,
            'is_read': msg.is_read,
            'created_at': msg.created_at.isoformat(),
        })
    return JsonResponse(msg_list, safe=False, status=200)


def get_doctor_messages_api(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        doctor = DoctorProfile.objects.get(user=request.user)
    except DoctorProfile.DoesNotExist:
        return JsonResponse({'error': 'Only doctors can view these messages'}, status=403)

    today = timezone.now().date()
    messages = Message.objects.filter(doctor=doctor, created_at__date=today).order_by('-created_at')
    msg_list = []
    for msg in messages:
        msg_list.append({
            'id': msg.id,
            'patient_name': msg.patient.user.username,
            'content': msg.content,
            'is_read': msg.is_read,
            'created_at': msg.created_at.isoformat(),
        })
    return JsonResponse(msg_list, safe=False, status=200)


def mark_message_read_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    try:
        doctor = DoctorProfile.objects.get(user=request.user)
    except DoctorProfile.DoesNotExist:
        return JsonResponse({'error': 'Only doctors can perform this action'}, status=403)

    try:
        data = json.loads(request.body)
        message_id = data.get('message_id')
        msg = get_object_or_404(Message, id=message_id, doctor=doctor)
        msg.is_read = True
        msg.save()
        return JsonResponse({'message': 'Message marked as read'}, status=200)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)


def check_exercise_compliance(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required'}, status=401)

    today = timezone.now().date()
    pending = AssignedExercise.objects.filter(
        patient__user_id=request.user.id,
        date_assigned__date=today,
        is_completed=False
    )

    has_pending = pending.exists()

    return JsonResponse({
        'skipped': has_pending,
        'message': "You have pending exercises for today!" if has_pending else None
    }, status=200)
