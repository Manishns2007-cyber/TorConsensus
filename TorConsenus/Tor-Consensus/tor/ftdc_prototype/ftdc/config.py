"""
Production Configuration for TOR-Unveil FTDC System
====================================================

This module provides centralized configuration management with support for:
- Environment variables
- Multiple deployment environments (development, staging, production)
- Security settings
- Database configuration
- AI/ML model settings

Usage:
    from ftdc.config import get_config
    config = get_config()
"""

import os
import secrets
from datetime import timedelta


class BaseConfig:
    """Base configuration with defaults for all environments."""
    
    # Application info
    APP_NAME = "TOR-Unveil FTDC"
    APP_VERSION = "1.0.0"
    
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # File upload settings
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_UPLOAD_SIZE', 500 * 1024 * 1024))  # 500 MB default
    ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
    
    # Paths (can be overridden via environment)
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or os.path.join(BASE_DIR, 'uploads')
    RESULTS_FOLDER = os.environ.get('RESULTS_FOLDER') or os.path.join(BASE_DIR, 'results')
    MODELS_FOLDER = os.environ.get('MODELS_FOLDER') or os.path.join(BASE_DIR, 'ftdc', 'models')
    
    # Database
    DATABASE_PATH = os.environ.get('DATABASE_PATH') or os.path.join(BASE_DIR, 'ftdc_analysis.db')
    
    # AI/ML Settings
    AI_MODEL_PATH = os.environ.get('AI_MODEL_PATH') or os.path.join(BASE_DIR, 'ftdc', 'models', 'ai_risk_model.joblib')
    AI_TRAINING_MIN_SAMPLES = int(os.environ.get('AI_TRAINING_MIN_SAMPLES', 100))
    AI_CONFIDENCE_THRESHOLD = float(os.environ.get('AI_CONFIDENCE_THRESHOLD', 0.7))
    
    # Tor Consensus Settings
    CONSENSUS_CACHE_TTL = int(os.environ.get('CONSENSUS_CACHE_TTL', 3600))  # 1 hour
    CONSENSUS_RELAY_LIMIT = int(os.environ.get('CONSENSUS_RELAY_LIMIT', 500))
    ONIONOO_TIMEOUT = int(os.environ.get('ONIONOO_TIMEOUT', 10))
    
    # Analysis Settings
    DEFAULT_TIME_WINDOW_MS = int(os.environ.get('DEFAULT_TIME_WINDOW_MS', 50))
    MAX_CONCURRENT_ANALYSES = int(os.environ.get('MAX_CONCURRENT_ANALYSES', 5))
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = os.environ.get('LOG_FILE')  # None = stdout only
    
    # CORS Settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', 'false').lower() == 'true'
    RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '100 per hour')
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)


class DevelopmentConfig(BaseConfig):
    """Development environment configuration."""
    
    DEBUG = True
    TESTING = False
    ENV = 'development'
    
    # More verbose logging in development
    LOG_LEVEL = 'DEBUG'
    
    # Relaxed security for development
    CORS_ORIGINS = '*'


class TestingConfig(BaseConfig):
    """Testing environment configuration."""
    
    DEBUG = False
    TESTING = True
    ENV = 'testing'
    
    # Use separate test database
    DATABASE_PATH = os.path.join(BaseConfig.BASE_DIR, 'test_ftdc_analysis.db')
    
    # Smaller limits for faster tests
    CONSENSUS_RELAY_LIMIT = 50
    AI_TRAINING_MIN_SAMPLES = 10


class StagingConfig(BaseConfig):
    """Staging environment configuration."""
    
    DEBUG = False
    TESTING = False
    ENV = 'staging'
    
    LOG_LEVEL = 'INFO'
    RATE_LIMIT_ENABLED = True


class ProductionConfig(BaseConfig):
    """Production environment configuration."""
    
    DEBUG = False
    TESTING = False
    ENV = 'production'
    
    # Strict security in production
    SECRET_KEY = os.environ.get('SECRET_KEY')  # MUST be set in production
    
    # Production logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'WARNING')
    LOG_FILE = os.environ.get('LOG_FILE', '/var/log/tor-unveil/app.log')
    
    # Restricted CORS in production
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'https://tor-unveil.tnpolice.gov.in')
    
    # Rate limiting enabled
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_DEFAULT = '50 per hour'
    
    # Ensure secret key is set
    @classmethod
    def validate(cls):
        """Validate production configuration."""
        errors = []
        
        if not cls.SECRET_KEY:
            errors.append("SECRET_KEY must be set in production environment")
        
        if cls.SECRET_KEY and len(cls.SECRET_KEY) < 32:
            errors.append("SECRET_KEY must be at least 32 characters")
        
        if errors:
            raise ValueError(f"Production configuration errors: {'; '.join(errors)}")
        
        return True


# Configuration mapping
config_map = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config(env=None):
    """
    Get configuration for the specified environment.
    
    Args:
        env: Environment name ('development', 'testing', 'staging', 'production')
             If not specified, reads from APP_ENV or defaults to 'development'
    
    Returns:
        Configuration class for the specified environment
    """
    if env is None:
        env = os.environ.get('APP_ENV', 'development')
    
    config_class = config_map.get(env, config_map['default'])
    
    # Validate production config
    if env == 'production':
        config_class.validate()
    
    return config_class


def init_directories(config):
    """Ensure all required directories exist."""
    directories = [
        config.UPLOAD_FOLDER,
        config.RESULTS_FOLDER,
        config.MODELS_FOLDER,
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Create log directory if file logging is enabled
    if config.LOG_FILE:
        log_dir = os.path.dirname(config.LOG_FILE)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
