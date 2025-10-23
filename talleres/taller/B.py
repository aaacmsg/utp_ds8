#!/usr/bin/env python3
"""
Validador de Integridad de Firmware - SmartLife Solutions
"""

import hashlib
import json
import logging
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class FirmwareValidator:
    def __init__(self):
        self.expected_hashes = self.load_expected_hashes()
        
    def load_expected_hashes(self):
        """Carga hashes esperados de base de datos segura"""
        # En producción, cargar desde base de datos o servicio seguro
        return {
            "camera_firmware_v2.1": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234",
            "sensor_motion_v1.5": "b2c3d4e5f6789012345678901234567890123456789012345678901234a1",
            "smart_lock_v3.2": "c3d4e5f6789012345678901234567890123456789012345678901234a1b2"
        }
    
    def validate_firmware(self, firmware_path, firmware_name):
        """Valida integridad del firmware"""
        try:
            calculated_hash = self.calculate_sha256(firmware_path)
            expected_hash = self.expected_hashes.get(firmware_name)
            
            if not expected_hash:
                logging.error(f"No expected hash found for {firmware_name}")
                return False
            
            if calculated_hash == expected_hash:
                logging.info(f"Firmware {firmware_name} validation successful")
                return True
            else:
                logging.error(f"Firmware validation failed for {firmware_name}")
                logging.error(f"Expected: {expected_hash}")
                logging.error(f"Got: {calculated_hash}")
                return False
                
        except Exception as e:
            logging.error(f"Firmware validation error: {e}")
            return False
    
    def calculate_sha256(self, file_path):
        """Calcula hash SHA-256 del archivo"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()

def main():
    if len(sys.argv) != 3:
        print("Uso: python firmware_validator.py <firmware_path> <firmware_name>")
        sys.exit(1)
    
    firmware_path = sys.argv[1]
    firmware_name = sys.argv[2]
    
    validator = FirmwareValidator()
    is_valid = validator.validate_firmware(firmware_path, firmware_name)
    
    if is_valid:
        print("✓ Firmware válido - Puede proceder con la actualización")
        sys.exit(0)
    else:
        print("✗ Firmware inválido - NO proceda con la actualización")
        sys.exit(1)

if __name__ == "__main__":
    main()