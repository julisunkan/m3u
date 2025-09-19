
import os
import re
import requests
import random
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, flash, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Index
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "your-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///m3u_player.db")
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Performance optimization settings
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year cache for static files

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Ensure database directory exists for SQLite
db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
if db_path and '/' in db_path:
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

db.init_app(app)

# Database Models
class Playlist(db.Model):
    __tablename__ = 'playlists'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)  # Added index
    url = db.Column(db.Text, nullable=True)  # Store original M3U URL for refresh
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)  # Added index
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_refresh = db.Column(db.DateTime, nullable=True)
    is_cached = db.Column(db.Boolean, default=False)

    # Relationship to channels
    channels = db.relationship('Channel', backref='playlist', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Playlist {self.name}>'

    @property
    def channel_count(self):
        """Get channel count efficiently"""
        return self.channels.count()

    def needs_refresh(self, hours=24):
        """Check if playlist needs refresh (default 24 hours)"""
        if not self.last_refresh:
            return True
        return datetime.utcnow() - self.last_refresh > timedelta(hours=hours)

class Channel(db.Model):
    __tablename__ = 'channels'

    id = db.Column(db.Integer, primary_key=True)
    playlist_id = db.Column(db.Integer, db.ForeignKey('playlists.id'), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)  # Added index for search
    logo_url = db.Column(db.Text, nullable=True)
    group_title = db.Column(db.String(100), nullable=True, index=True)  # Channel category
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to streams
    streams = db.relationship('Stream', backref='channel', lazy='dynamic', cascade='all, delete-orphan')

    # Create composite index for efficient pagination
    __table_args__ = (
        Index('idx_playlist_name', 'playlist_id', 'name'),
    )

    def __repr__(self):
        return f'<Channel {self.name}>'

    @property
    def stream_count(self):
        """Get stream count efficiently"""
        return self.streams.count()

    @property
    def primary_stream(self):
        """Get the primary stream (first one)"""
        return self.streams.first()

class Stream(db.Model):
    __tablename__ = 'streams'

    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False, index=True)
    resolution_label = db.Column(db.String(50), nullable=False, index=True)
    url = db.Column(db.Text, nullable=False)
    is_hls = db.Column(db.Boolean, default=False)  # Track if it's HLS for optimization
    needs_proxy = db.Column(db.Boolean, default=False)  # Track if proxy is needed

    def __repr__(self):
        return f'<Stream {self.resolution_label}: {self.url[:50]}...>'

class ProxyServer(db.Model):
    __tablename__ = 'proxy_servers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    proxy_type = db.Column(db.String(20), nullable=False)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(100), nullable=True)
    country_code = db.Column(db.String(2), nullable=True)
    is_active = db.Column(db.Boolean, default=True, index=True)  # Added index
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ProxyServer {self.name}: {self.host}:{self.port}>'

class AdminSetting(db.Model):
    __tablename__ = 'admin_settings'

    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    setting_value = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<AdminSetting {self.setting_key}>'

    @classmethod
    def get_setting(cls, key, default=None):
        """Get a setting value by key"""
        setting = cls.query.filter_by(setting_key=key).first()
        return setting.setting_value if setting else default

    @classmethod
    def set_setting(cls, key, value):
        """Set a setting value by key"""
        setting = cls.query.filter_by(setting_key=key).first()
        if setting:
            setting.setting_value = value
            setting.updated_at = datetime.utcnow()
        else:
            setting = cls()
            setting.setting_key = key
            setting.setting_value = value
            db.session.add(setting)
        db.session.commit()
        return setting

# Optimized M3U Parser Class
class M3UParser:
    @staticmethod
    def parse_content(content):
        """Parse M3U content and extract channel information with metadata"""
        channels = []
        lines = content.strip().split('\n')

        current_channel = None
        current_logo = None
        current_group = None
        
        for line in lines:
            line = line.strip()

            if line.startswith('#EXTINF:'):
                # Enhanced parsing for logos and groups
                # Format: #EXTINF:duration,channel_name
                # Extended: #EXTINF:duration tvg-logo="logo_url" group-title="group",channel_name
                
                # Extract logo URL
                logo_match = re.search(r'tvg-logo="([^"]*)"', line)
                current_logo = logo_match.group(1) if logo_match else None
                
                # Extract group title
                group_match = re.search(r'group-title="([^"]*)"', line)
                current_group = group_match.group(1) if group_match else None
                
                # Extract channel name
                name_match = re.search(r'#EXTINF:[^,]*,(.+)', line)
                if name_match:
                    current_channel = name_match.group(1).strip()
                    
            elif line and not line.startswith('#') and current_channel:
                # This is a stream URL
                is_hls = '.m3u8' in line.lower()
                
                channels.append({
                    'name': current_channel,
                    'url': line,
                    'logo_url': current_logo,
                    'group_title': current_group,
                    'is_hls': is_hls
                })
                current_channel = None
                current_logo = None
                current_group = None

        return channels

    @staticmethod
    def fetch_from_url(url):
        """Fetch M3U content from URL with caching headers"""
        try:
            headers = {
                'User-Agent': 'M3U-Player/1.0',
                'Cache-Control': 'no-cache'
            }
            response = requests.get(url, timeout=30, headers=headers)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            raise Exception(f"Failed to fetch M3U from URL: {str(e)}")

# Admin Configuration
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
DEFAULT_PASSWORD_HASH = 'scrypt:32768:8:1$edToewmbQDVlSTvH$23e5b57664780220ce12c1396ca2b3922f0c5868798df91902a695fabe2e4afc9f7a3a18c2de4707c0a09549f2fe8170a735135167c103d21bf096abb6690f9f'
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', DEFAULT_PASSWORD_HASH)

def get_admin_password_hash():
    """Get admin password hash from database first, then fallback to environment variable"""
    db_hash = AdminSetting.get_setting('admin_password_hash')
    return db_hash if db_hash else ADMIN_PASSWORD_HASH

# Initialize database tables at the end of the file
with app.app_context():
    db.create_all()

# Authentication helpers
def is_admin_logged_in():
    return session.get('admin_logged_in', False)

def require_admin(f):
    def decorated_function(*args, **kwargs):
        if not is_admin_logged_in():
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# CSRF Protection helpers
def generate_csrf_token():
    """Generate a CSRF token and store it in the session"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

def validate_csrf_token(token):
    """Validate the CSRF token against the session"""
    return token and session.get('_csrf_token') == token

# Make CSRF token available to templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)

# Optimized caching headers
@app.after_request
def add_cache_headers(response):
    """Add caching headers for static files and API responses"""
    if request.endpoint and 'static' in request.endpoint:
        response.cache_control.max_age = 31536000  # 1 year
        response.cache_control.public = True
    elif request.endpoint and request.endpoint.startswith('api_'):
        response.cache_control.max_age = 60  # 1 minute for API
    return response

# Routes
@app.route('/')
def index():
    """Optimized main page with pagination"""
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 24  # Optimized for grid layout

    # Build optimized query with joins
    query = Channel.query.join(Playlist)
    
    if search_query:
        # Use indexed search
        query = query.filter(Channel.name.ilike(f'%{search_query}%'))

    # Order by playlist and channel name for consistent pagination
    query = query.order_by(Playlist.name, Channel.name)

    # Paginate results with optimized loading
    channels = query.paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )

    # Get playlist count for stats
    playlist_count = Playlist.query.count()

    return render_template('index.html', 
                         channels=channels, 
                         search_query=search_query,
                         playlist_count=playlist_count)

@app.route('/api/channels')
def api_channels():
    """AJAX endpoint for channel loading"""
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 24

    query = Channel.query.join(Playlist)
    
    if search_query:
        query = query.filter(Channel.name.ilike(f'%{search_query}%'))

    query = query.order_by(Playlist.name, Channel.name)
    channels = query.paginate(page=page, per_page=per_page, error_out=False)

    # Return JSON for AJAX
    channel_data = []
    for channel in channels.items:
        channel_data.append({
            'id': channel.id,
            'name': channel.name,
            'playlist_name': channel.playlist.name,
            'stream_count': channel.stream_count,
            'logo_url': channel.logo_url,
            'group_title': channel.group_title
        })

    return jsonify({
        'channels': channel_data,
        'pagination': {
            'page': channels.page,
            'pages': channels.pages,
            'per_page': channels.per_page,
            'total': channels.total,
            'has_next': channels.has_next,
            'has_prev': channels.has_prev
        }
    })

@app.route('/play/<int:channel_id>')
def play_channel(channel_id):
    """Optimized play channel with lazy loading"""
    channel = Channel.query.options(db.joinedload(Channel.playlist)).get_or_404(channel_id)
    return render_template('player.html', channel=channel)

@app.route('/api/channel/<int:channel_id>/streams')
def get_channel_streams(channel_id):
    """Optimized API endpoint to get all streams for a channel"""
    channel = Channel.query.get_or_404(channel_id)
    streams = []
    
    for stream in channel.streams:
        streams.append({
            'id': stream.id,
            'resolution_label': stream.resolution_label,
            'url': stream.url,
            'is_hls': stream.is_hls,
            'needs_proxy': stream.needs_proxy
        })

    return jsonify({
        'channel': {
            'id': channel.id,
            'name': channel.name
        },
        'streams': streams
    })

@app.route('/api/channel/<int:channel_id>/status')
def check_channel_status(channel_id):
    """Lightweight channel status check"""
    channel = Channel.query.get_or_404(channel_id)
    
    if not channel.streams.first():
        return jsonify({'status': 'OFFLINE', 'reason': 'No streams available'})

    # Quick status check without full request
    stream = channel.streams.first()
    try:
        # Use HEAD request with short timeout
        response = requests.head(stream.url, timeout=3, allow_redirects=True)
        if response.status_code == 200:
            return jsonify({'status': 'ONLINE'})
        else:
            return jsonify({'status': 'OFFLINE', 'reason': f'HTTP {response.status_code}'})
    except requests.RequestException as e:
        return jsonify({'status': 'OFFLINE', 'reason': 'Connection failed'})

def get_proxy_for_stream(stream_url):
    """Get a suitable proxy server for the stream"""
    proxies = ProxyServer.query.filter_by(is_active=True).all()
    if not proxies:
        return None
    return random.choice(proxies)

def get_user_agents():
    """Return optimized user agents"""
    return [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]

@app.route('/proxy/<int:stream_id>')
def proxy_stream(stream_id):
    """Optimized proxy endpoint with efficient streaming"""
    stream = Stream.query.get_or_404(stream_id)
    
    # Check if proxy is actually needed
    if not stream.needs_proxy:
        return redirect(stream.url)

    try:
        headers = {
            'User-Agent': random.choice(get_user_agents()),
            'Accept': '*/*',
            'Connection': 'keep-alive'
        }

        proxy_server = get_proxy_for_stream(stream.url)
        proxies = None

        if proxy_server:
            if proxy_server.username and proxy_server.password:
                proxy_url = f"{proxy_server.proxy_type}://{proxy_server.username}:{proxy_server.password}@{proxy_server.host}:{proxy_server.port}"
            else:
                proxy_url = f"{proxy_server.proxy_type}://{proxy_server.host}:{proxy_server.port}"
            proxies = {'http': proxy_url, 'https': proxy_url}

        # Efficient streaming with smaller chunks
        def generate():
            with requests.get(stream.url, stream=True, timeout=30, 
                            headers=headers, proxies=proxies) as r:
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=4096):  # Smaller chunks
                    if chunk:
                        yield chunk

        # Determine content type
        url_lower = stream.url.lower()
        if url_lower.endswith('.mp4'):
            content_type = 'video/mp4'
        elif url_lower.endswith('.ts'):
            content_type = 'video/mp2t'
        elif url_lower.endswith('.m3u8'):
            content_type = 'application/vnd.apple.mpegurl'
        else:
            content_type = 'application/octet-stream'

        response = Response(generate(), content_type=content_type)
        response.headers['Cache-Control'] = 'no-cache'
        return response

    except requests.RequestException as e:
        return f"Error proxying stream: {str(e)}", 500

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            flash('Invalid security token. Please try again.', 'error')
            return render_template('admin_login.html')

        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME and password and check_password_hash(get_admin_password_hash(), password):
            session['admin_logged_in'] = True
            session.pop('_csrf_token', None)
            flash('Successfully logged in!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials!', 'error')

    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.pop('admin_logged_in', None)
    flash('Successfully logged out!', 'success')
    return redirect(url_for('index'))

@app.route('/admin')
@require_admin
def admin_dashboard():
    """Optimized admin dashboard"""
    # Use subquery for efficient counting
    playlists = db.session.query(
        Playlist,
        db.func.count(Channel.id).label('channel_count')
    ).outerjoin(Channel).group_by(Playlist.id).order_by(Playlist.created_at.desc()).all()
    
    return render_template('admin_dashboard.html', playlists=playlists)

@app.route('/admin/import', methods=['GET', 'POST'])
@require_admin
def admin_import_playlist():
    """Optimized import with caching"""
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            flash('Invalid security token. Please try again.', 'error')
            return render_template('admin_import.html')

        playlist_name = request.form.get('playlist_name')
        m3u_url = request.form.get('m3u_url')
        m3u_file = request.files.get('m3u_file')

        if not playlist_name:
            flash('Playlist name is required!', 'error')
            return render_template('admin_import.html')

        try:
            # Get M3U content
            if m3u_url:
                content = M3UParser.fetch_from_url(m3u_url)
            elif m3u_file and m3u_file.filename:
                content = m3u_file.read().decode('utf-8')
            else:
                flash('Please provide either M3U URL or upload a file!', 'error')
                return render_template('admin_import.html')

            # Parse channels
            channels_data = M3UParser.parse_content(content)

            if not channels_data:
                flash('No channels found in M3U playlist!', 'error')
                return render_template('admin_import.html')

            # Create playlist with caching info
            playlist = Playlist()
            playlist.name = playlist_name
            playlist.url = m3u_url  # Store URL for refresh
            playlist.is_cached = True
            playlist.last_refresh = datetime.utcnow()
            db.session.add(playlist)
            db.session.flush()

            # Batch insert channels and streams
            for channel_data in channels_data:
                channel = Channel()
                channel.playlist_id = playlist.id
                channel.name = channel_data['name']
                channel.logo_url = channel_data.get('logo_url')
                channel.group_title = channel_data.get('group_title')
                db.session.add(channel)
                db.session.flush()

                # Create stream with optimization flags
                stream = Stream()
                stream.channel_id = channel.id
                stream.resolution_label = 'SD'
                stream.url = channel_data['url']
                stream.is_hls = channel_data.get('is_hls', False)
                stream.needs_proxy = not channel_data.get('is_hls', False)  # HLS usually doesn't need proxy
                db.session.add(stream)

            db.session.commit()
            flash(f'Successfully imported {len(channels_data)} channels!', 'success')
            return redirect(url_for('admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error importing playlist: {str(e)}', 'error')

    return render_template('admin_import.html')

@app.route('/admin/playlist/<int:playlist_id>/refresh', methods=['POST'])
@require_admin
def admin_refresh_playlist(playlist_id):
    """Refresh playlist from original URL"""
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        flash('Invalid security token. Please try again.', 'error')
        return redirect(url_for('admin_view_playlist', playlist_id=playlist_id))

    playlist = Playlist.query.get_or_404(playlist_id)
    
    if not playlist.url:
        flash('No URL stored for this playlist - cannot refresh', 'error')
        return redirect(url_for('admin_view_playlist', playlist_id=playlist_id))

    try:
        # Fetch fresh content
        content = M3UParser.fetch_from_url(playlist.url)
        channels_data = M3UParser.parse_content(content)

        if not channels_data:
            flash('No channels found in refreshed playlist!', 'error')
            return redirect(url_for('admin_view_playlist', playlist_id=playlist_id))

        # Clear existing channels
        playlist.channels.delete()

        # Add new channels
        for channel_data in channels_data:
            channel = Channel()
            channel.playlist_id = playlist.id
            channel.name = channel_data['name']
            channel.logo_url = channel_data.get('logo_url')
            channel.group_title = channel_data.get('group_title')
            db.session.add(channel)
            db.session.flush()

            stream = Stream()
            stream.channel_id = channel.id
            stream.resolution_label = 'SD'
            stream.url = channel_data['url']
            stream.is_hls = channel_data.get('is_hls', False)
            stream.needs_proxy = not channel_data.get('is_hls', False)
            db.session.add(stream)

        playlist.last_refresh = datetime.utcnow()
        playlist.updated_at = datetime.utcnow()
        db.session.commit()

        flash(f'Successfully refreshed playlist with {len(channels_data)} channels!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error refreshing playlist: {str(e)}', 'error')

    return redirect(url_for('admin_view_playlist', playlist_id=playlist_id))

@app.route('/admin/playlist/<int:playlist_id>/delete', methods=['POST'])
@require_admin
def admin_delete_playlist(playlist_id):
    """Delete a playlist"""
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        flash('Invalid security token. Please try again.', 'error')
        return redirect(url_for('admin_dashboard'))

    playlist = Playlist.query.get_or_404(playlist_id)
    playlist_name = playlist.name

    db.session.delete(playlist)
    db.session.commit()

    flash(f'Playlist "{playlist_name}" deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/playlist/<int:playlist_id>')
@require_admin
def admin_view_playlist(playlist_id):
    """View and manage channels in a playlist with pagination"""
    playlist = Playlist.query.get_or_404(playlist_id)
    page = request.args.get('page', 1, type=int)
    
    channels = playlist.channels.order_by(Channel.name).paginate(
        page=page, per_page=50, error_out=False
    )
    
    return render_template('admin_playlist.html', playlist=playlist, channels=channels)

@app.route('/admin/channel/<int:channel_id>')
@require_admin
def admin_view_channel(channel_id):
    """View and manage streams for a channel"""
    channel = Channel.query.get_or_404(channel_id)
    return render_template('admin_channel.html', channel=channel)

@app.route('/admin/channel/<int:channel_id>/add_stream', methods=['POST'])
@require_admin
def admin_add_stream(channel_id):
    """Add a new stream to a channel"""
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        flash('Invalid security token. Please try again.', 'error')
        return redirect(url_for('admin_view_channel', channel_id=channel_id))

    channel = Channel.query.get_or_404(channel_id)

    resolution_label = request.form.get('resolution_label')
    url = request.form.get('url')

    if not resolution_label or not url:
        flash('Both resolution label and URL are required!', 'error')
        return redirect(url_for('admin_view_channel', channel_id=channel_id))

    stream = Stream()
    stream.channel_id = channel_id
    stream.resolution_label = resolution_label
    stream.url = url
    stream.is_hls = '.m3u8' in url.lower()
    stream.needs_proxy = not stream.is_hls
    db.session.add(stream)
    db.session.commit()

    flash(f'Stream "{resolution_label}" added successfully!', 'success')
    return redirect(url_for('admin_view_channel', channel_id=channel_id))

@app.route('/admin/stream/<int:stream_id>/delete', methods=['POST'])
@require_admin
def admin_delete_stream(stream_id):
    """Delete a stream"""
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        flash('Invalid security token. Please try again.', 'error')
        return redirect(url_for('admin_dashboard'))

    stream = Stream.query.get_or_404(stream_id)
    channel_id = stream.channel_id

    db.session.delete(stream)
    db.session.commit()

    flash('Stream deleted successfully!', 'success')
    return redirect(url_for('admin_view_channel', channel_id=channel_id))

@app.route('/admin/proxies')
@require_admin
def admin_proxies():
    """Manage proxy servers"""
    proxies = ProxyServer.query.order_by(ProxyServer.created_at.desc()).all()
    return render_template('admin_proxies.html', proxies=proxies)

@app.route('/admin/proxies/add', methods=['GET', 'POST'])
@require_admin
def admin_add_proxy():
    """Add new proxy server"""
    if request.method == 'POST':
        name = request.form.get('name')
        proxy_type = request.form.get('proxy_type')
        host = request.form.get('host')
        port = request.form.get('port', type=int)
        username = request.form.get('username')
        password = request.form.get('password')
        country_code = request.form.get('country_code')

        if not all([name, proxy_type, host, port]):
            flash('Name, type, host, and port are required!', 'error')
            return render_template('admin_add_proxy.html')

        proxy = ProxyServer()
        proxy.name = name
        proxy.proxy_type = proxy_type
        proxy.host = host
        proxy.port = port
        proxy.username = username if username else None
        proxy.password = password if password else None
        proxy.country_code = country_code.upper() if country_code else None
        db.session.add(proxy)
        db.session.commit()

        flash(f'Proxy server "{name}" added successfully!', 'success')
        return redirect(url_for('admin_proxies'))

    return render_template('admin_add_proxy.html')

@app.route('/admin/proxies/<int:proxy_id>/toggle', methods=['POST'])
@require_admin
def admin_toggle_proxy(proxy_id):
    """Toggle proxy server active status"""
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        flash('Invalid security token. Please try again.', 'error')
        return redirect(url_for('admin_proxies'))

    proxy = ProxyServer.query.get_or_404(proxy_id)
    proxy.is_active = not proxy.is_active
    db.session.commit()

    status = 'activated' if proxy.is_active else 'deactivated'
    flash(f'Proxy server "{proxy.name}" {status}!', 'success')
    return redirect(url_for('admin_proxies'))

@app.route('/admin/proxies/<int:proxy_id>/delete', methods=['POST'])
@require_admin
def admin_delete_proxy(proxy_id):
    """Delete proxy server"""
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        flash('Invalid security token. Please try again.', 'error')
        return redirect(url_for('admin_proxies'))

    proxy = ProxyServer.query.get_or_404(proxy_id)
    proxy_name = proxy.name

    db.session.delete(proxy)
    db.session.commit()

    flash(f'Proxy server "{proxy_name}" deleted successfully!', 'success')
    return redirect(url_for('admin_proxies'))

@app.route('/admin/change-password', methods=['GET', 'POST'])
@require_admin
def admin_change_password():
    """Change admin password"""
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            flash('Invalid security token. Please try again.', 'error')
            return render_template('admin_change_password.html')

        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required!', 'error')
            return render_template('admin_change_password.html')

        if not check_password_hash(get_admin_password_hash(), current_password):
            flash('Current password is incorrect!', 'error')
            return render_template('admin_change_password.html')

        if new_password != confirm_password:
            flash('New passwords do not match!', 'error')
            return render_template('admin_change_password.html')

        if len(new_password) < 8:
            flash('New password must be at least 8 characters long!', 'error')
            return render_template('admin_change_password.html')

        new_password_hash = generate_password_hash(new_password)
        AdminSetting.set_setting('admin_password_hash', new_password_hash)
        session.pop('_csrf_token', None)

        flash('Password changed successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_change_password.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
