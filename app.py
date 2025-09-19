import os
import re
import requests
import random
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)

# Database Models
class Playlist(db.Model):
    __tablename__ = 'playlists'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to channels
    channels = db.relationship('Channel', backref='playlist', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Playlist {self.name}>'

class Channel(db.Model):
    __tablename__ = 'channels'
    
    id = db.Column(db.Integer, primary_key=True)
    playlist_id = db.Column(db.Integer, db.ForeignKey('playlists.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    
    # Relationship to streams
    streams = db.relationship('Stream', backref='channel', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Channel {self.name}>'

class Stream(db.Model):
    __tablename__ = 'streams'
    
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False)
    resolution_label = db.Column(db.String(50), nullable=False)  # SD, HD, 720p, 1080p, 4K, etc.
    url = db.Column(db.Text, nullable=False)
    
    def __repr__(self):
        return f'<Stream {self.resolution_label}: {self.url[:50]}...>'

class ProxyServer(db.Model):
    __tablename__ = 'proxy_servers'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    proxy_type = db.Column(db.String(20), nullable=False)  # http, socks5, etc.
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(100), nullable=True)
    country_code = db.Column(db.String(2), nullable=True)  # US, UK, CA, etc.
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ProxyServer {self.name}: {self.host}:{self.port}>'

# M3U Parser Class
class M3UParser:
    @staticmethod
    def parse_content(content):
        """Parse M3U content and extract channel information"""
        channels = []
        lines = content.strip().split('\n')
        
        current_channel = None
        for line in lines:
            line = line.strip()
            
            if line.startswith('#EXTINF:'):
                # Extract channel name from EXTINF line
                # Format: #EXTINF:duration,channel_name
                match = re.search(r'#EXTINF:[^,]*,(.+)', line)
                if match:
                    current_channel = match.group(1).strip()
            elif line and not line.startswith('#') and current_channel:
                # This is a stream URL
                channels.append({
                    'name': current_channel,
                    'url': line
                })
                current_channel = None
        
        return channels
    
    @staticmethod
    def fetch_from_url(url):
        """Fetch M3U content from URL"""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            raise Exception(f"Failed to fetch M3U from URL: {str(e)}")

# Admin Configuration
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
# Default password hash for 'admin123' - change in production by setting ADMIN_PASSWORD_HASH env variable
DEFAULT_PASSWORD_HASH = 'scrypt:32768:8:1$edToewmbQDVlSTvH$23e5b57664780220ce12c1396ca2b3922f0c5868798df91902a695fabe2e4afc9f7a3a18c2de4707c0a09549f2fe8170a735135167c103d21bf096abb6690f9f'
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', DEFAULT_PASSWORD_HASH)

def init_db():
    """Initialize the database"""
    with app.app_context():
        db.create_all()


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

# Routes
@app.route('/')
def index():
    """Main page - channel browser"""
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Build query
    query = Channel.query
    if search_query:
        query = query.filter(Channel.name.ilike(f'%{search_query}%'))
    
    # Paginate results
    channels = query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('index.html', 
                         channels=channels, 
                         search_query=search_query)

@app.route('/play/<int:channel_id>')
def play_channel(channel_id):
    """Play a specific channel"""
    channel = Channel.query.get_or_404(channel_id)
    return render_template('player.html', channel=channel)

@app.route('/api/channel/<int:channel_id>/streams')
def get_channel_streams(channel_id):
    """API endpoint to get all streams for a channel"""
    channel = Channel.query.get_or_404(channel_id)
    streams = [{
        'id': stream.id,
        'resolution_label': stream.resolution_label,
        'url': stream.url
    } for stream in channel.streams]
    
    return jsonify({
        'channel': {
            'id': channel.id,
            'name': channel.name
        },
        'streams': streams
    })

@app.route('/api/channel/<int:channel_id>/status')
def check_channel_status(channel_id):
    """API endpoint to check if a channel's streams are online"""
    channel = Channel.query.get_or_404(channel_id)
    
    if not channel.streams:
        return jsonify({'status': 'OFFLINE', 'reason': 'No streams available'})
    
    # Check the first stream to determine if channel is online
    stream = channel.streams[0]
    try:
        # Make a HEAD request to check if stream is accessible
        response = requests.head(stream.url, timeout=5, allow_redirects=True)
        if response.status_code == 200:
            return jsonify({'status': 'ONLINE'})
        else:
            return jsonify({'status': 'OFFLINE', 'reason': f'HTTP {response.status_code}'})
    except requests.RequestException as e:
        return jsonify({'status': 'OFFLINE', 'reason': str(e)})

@app.route('/api/channels/status')
def check_all_channels_status():
    """API endpoint to check status of all channels"""
    channels = Channel.query.all()
    status_data = []
    
    for channel in channels:
        if not channel.streams:
            status = 'OFFLINE'
        else:
            try:
                # Quick check of first stream
                response = requests.head(channel.streams[0].url, timeout=3, allow_redirects=True)
                status = 'ONLINE' if response.status_code == 200 else 'OFFLINE'
            except:
                status = 'OFFLINE'
        
        status_data.append({
            'id': channel.id,
            'status': status
        })
    
    return jsonify({'channels': status_data})

def get_proxy_for_stream(stream_url):
    """Get a suitable proxy server for the stream"""
    # Get active proxy servers
    proxies = ProxyServer.query.filter_by(is_active=True).all()
    
    if not proxies:
        return None
    
    # Simple round-robin selection (can be enhanced with geo-location logic)
    # TODO: Add country-aware selection and health checks
    return random.choice(proxies)

def get_user_agents():
    """Return a list of realistic user agents for geo-blocking bypass"""
    return [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0'
    ]

@app.route('/proxy/<int:stream_id>')
def proxy_stream(stream_id):
    """Enhanced proxy endpoint for non-HLS streams with geo-blocking bypass"""
    stream = Stream.query.get_or_404(stream_id)
    
    try:
        # Prepare headers for geo-blocking bypass
        headers = {
            'User-Agent': random.choice(get_user_agents()),
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Get proxy configuration
        proxy_server = get_proxy_for_stream(stream.url)
        proxies = None
        
        if proxy_server:
            if proxy_server.username and proxy_server.password:
                proxy_url = f"{proxy_server.proxy_type}://{proxy_server.username}:{proxy_server.password}@{proxy_server.host}:{proxy_server.port}"
            else:
                proxy_url = f"{proxy_server.proxy_type}://{proxy_server.host}:{proxy_server.port}"
            
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
        
        # Stream the content
        def generate():
            with requests.get(stream.url, stream=True, timeout=30, 
                            headers=headers, proxies=proxies, 
                            verify=True) as r:
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        yield chunk
        
        # Determine content type based on URL
        url_lower = stream.url.lower()
        if url_lower.endswith('.mp4'):
            content_type = 'video/mp4'
        elif url_lower.endswith('.ts'):
            content_type = 'video/mp2t'
        elif url_lower.endswith('.aac'):
            content_type = 'audio/aac'
        else:
            content_type = 'application/octet-stream'
        
        response = Response(generate(), content_type=content_type)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    
    except requests.RequestException as e:
        return f"Error proxying stream: {str(e)}", 500

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
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
    """Admin dashboard - manage playlists and channels"""
    playlists = Playlist.query.order_by(Playlist.created_at.desc()).all()
    return render_template('admin_dashboard.html', playlists=playlists)

@app.route('/admin/import', methods=['GET', 'POST'])
@require_admin
def admin_import_playlist():
    """Import M3U playlist"""
    if request.method == 'POST':
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
            
            # Create playlist
            playlist = Playlist(name=playlist_name)
            db.session.add(playlist)
            db.session.flush()  # Get the playlist ID
            
            # Create channels and streams
            for channel_data in channels_data:
                channel = Channel(
                    playlist_id=playlist.id,
                    name=channel_data['name']
                )
                db.session.add(channel)
                db.session.flush()  # Get the channel ID
                
                # Create default stream (assume SD quality if not specified)
                stream = Stream(
                    channel_id=channel.id,
                    resolution_label='SD',
                    url=channel_data['url']
                )
                db.session.add(stream)
            
            db.session.commit()
            flash(f'Successfully imported {len(channels_data)} channels!', 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error importing playlist: {str(e)}', 'error')
    
    return render_template('admin_import.html')

@app.route('/admin/playlist/<int:playlist_id>/delete', methods=['POST'])
@require_admin
def admin_delete_playlist(playlist_id):
    """Delete a playlist"""
    playlist = Playlist.query.get_or_404(playlist_id)
    playlist_name = playlist.name
    
    db.session.delete(playlist)
    db.session.commit()
    
    flash(f'Playlist "{playlist_name}" deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/playlist/<int:playlist_id>')
@require_admin
def admin_view_playlist(playlist_id):
    """View and manage channels in a playlist"""
    playlist = Playlist.query.get_or_404(playlist_id)
    return render_template('admin_playlist.html', playlist=playlist)

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
    channel = Channel.query.get_or_404(channel_id)
    
    resolution_label = request.form.get('resolution_label')
    url = request.form.get('url')
    
    if not resolution_label or not url:
        flash('Both resolution label and URL are required!', 'error')
        return redirect(url_for('admin_view_channel', channel_id=channel_id))
    
    stream = Stream(
        channel_id=channel_id,
        resolution_label=resolution_label,
        url=url
    )
    db.session.add(stream)
    db.session.commit()
    
    flash(f'Stream "{resolution_label}" added successfully!', 'success')
    return redirect(url_for('admin_view_channel', channel_id=channel_id))

@app.route('/admin/stream/<int:stream_id>/delete', methods=['POST'])
@require_admin
def admin_delete_stream(stream_id):
    """Delete a stream"""
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
        
        proxy = ProxyServer(
            name=name,
            proxy_type=proxy_type,
            host=host,
            port=port,
            username=username if username else None,
            password=password if password else None,
            country_code=country_code.upper() if country_code else None
        )
        db.session.add(proxy)
        db.session.commit()
        
        flash(f'Proxy server "{name}" added successfully!', 'success')
        return redirect(url_for('admin_proxies'))
    
    return render_template('admin_add_proxy.html')

@app.route('/admin/proxies/<int:proxy_id>/toggle', methods=['POST'])
@require_admin
def admin_toggle_proxy(proxy_id):
    """Toggle proxy server active status"""
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
    proxy = ProxyServer.query.get_or_404(proxy_id)
    proxy_name = proxy.name
    
    db.session.delete(proxy)
    db.session.commit()
    
    flash(f'Proxy server "{proxy_name}" deleted successfully!', 'success')
    return redirect(url_for('admin_proxies'))

