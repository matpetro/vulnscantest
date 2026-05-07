import os
from flask_sqlalchemy import SQLAlchemy
import redis as redis_lib

db = SQLAlchemy()

redis_client = redis_lib.Redis(
    host=os.environ.get('REDIS_HOST', 'localhost'),
    port=int(os.environ.get('REDIS_PORT', 6379)),
    db=0,
    decode_responses=False,
    socket_connect_timeout=5,
)
