#!/usr/bin/env python3
'''
Defines a module that encrypts passwords
'''
import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes the password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Checks if the hashed password was formed from the given password"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
