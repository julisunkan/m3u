# M3U Player

## Overview

M3U Player is a Flask-based web application for managing and streaming IPTV playlists. The application allows administrators to import M3U playlist files (either via URL or file upload), organize channels with multiple resolution streams, and provides an intuitive player interface for end users. The system features a dual-interface design with an admin panel for content management and a public channel browser for streaming.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Template Engine**: Jinja2 templates with Bootstrap 5 for responsive UI
- **JavaScript Libraries**: hls.js for HLS stream playback with adaptive bitrate support
- **Responsive Design**: Mobile-first approach using Bootstrap grid system
- **Sticky Video Player**: Fixed positioning for continuous playback while browsing
- **Component Structure**: Base template with extending child templates for consistent layout

### Backend Architecture
- **Framework**: Flask with SQLAlchemy ORM for database operations
- **Database Schema**: Three-tier hierarchy (Playlists → Channels → Streams)
- **Session Management**: Flask sessions with configurable secret key
- **File Handling**: Werkzeug utilities for secure file uploads with size limits
- **Authentication**: Simple session-based admin authentication
- **Stream Proxy**: Flask endpoint for proxying non-HLS streams

### Data Storage Design
- **Database**: SQLite for local development with easy migration path
- **Schema Structure**:
  - `playlists`: Core playlist container with name and timestamps
  - `channels`: Individual channels linked to playlists
  - `streams`: Multiple resolution URLs per channel for quality switching
- **Relationships**: Cascade delete relationships to maintain data integrity
- **File Storage**: Local uploads directory for M3U file processing

### Authentication & Authorization
- **Admin System**: Environment variable-based credentials
- **Session Management**: Flask session storage for admin state
- **Access Control**: Decorator-based route protection for admin endpoints
- **Public Access**: Unrestricted channel browsing and streaming

## External Dependencies

### Frontend Libraries
- **Bootstrap 5**: CSS framework for responsive design and components
- **Bootstrap Icons**: Icon library for consistent UI elements
- **hls.js**: JavaScript library for HLS stream playback and resolution switching

### Backend Packages
- **Flask**: Core web framework
- **Flask-SQLAlchemy**: ORM for database operations
- **Werkzeug**: Security utilities for password hashing and file handling
- **Requests**: HTTP library for fetching M3U playlists from URLs

### Database
- **SQLite**: File-based database for development (easily replaceable with PostgreSQL)

### Stream Sources
- **M3U Playlists**: Support for both URL-based and file upload imports
- **HLS Streams**: Native support for .m3u8 adaptive streaming
- **Direct Media**: Proxy support for MP4, TS, and other direct media formats

### Infrastructure
- **File System**: Local storage for uploaded M3U files and static assets
- **Environment Variables**: Configuration management for secrets and settings