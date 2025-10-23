#!/usr/bin/env python3
"""
Sistema de Seguridad IoT - SmartLife Solutions
Módulo Principal de Monitoreo y Protección
"""

import asyncio
import logging
import hashlib
import hmac
import json
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import psutil
from scapy.all import sniff, IP, TCP, UDP
import socket
import threading
import time

class IoTSecuritySystem:
    def __init__(self):
        self.authorized_devices = set()
        self.suspicious_activities = []
        self.encryption_key = self.generate_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Configurar logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('iot_security.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def generate_encryption_key(self):
        """Genera clave de cifrado para datos sensibles"""
        password = b"iot_security_key_2024"
        salt = b"smartlife_salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encrypt_data(self, data):
        """Cifra datos sensibles antes de transmisión"""
        if isinstance(data, dict):
            data = json.dumps(data)
        encrypted_data = self.cipher_suite.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()

    def decrypt_data(self, encrypted_data):
        """Descifra datos recibidos"""
        try:
            encrypted_data = base64.urlsafe_b64decode(encrypted_data)
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            self.logger.error(f"Error decrypting data: {e}")
            return None

class NetworkMonitor:
    def __init__(self, security_system):
        self.security_system = security_system
        self.known_macs = set()
        self.network_stats = {}
        
    def start_monitoring(self):
        """Inicia monitoreo de red en hilos separados"""
        threading.Thread(target=self.monitor_network_traffic, daemon=True).start()
        threading.Thread(target=self.detect_new_devices, daemon=True).start()
        threading.Thread(target=self.analyze_bandwidth, daemon=True).start()

    def monitor_network_traffic(self):
        """Monitorea tráfico de red en busca de actividades sospechosas"""
        def packet_handler(packet):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Detectar conexiones sospechosas
                if self.is_suspicious_connection(src_ip, dst_ip, packet):
                    alert_msg = f"Suspicious connection: {src_ip} -> {dst_ip}"
                    self.security_system.logger.warning(alert_msg)
                    self.security_system.suspicious_activities.append({
                        'timestamp': datetime.now().isoformat(),
                        'type': 'suspicious_connection',
                        'source': src_ip,
                        'destination': dst_ip,
                        'protocol': packet.proto
                    })

        sniff(prn=packet_handler, filter="ip", store=0)

    def is_suspicious_connection(self, src_ip, dst_ip, packet):
        """Determina si una conexión es sospechosa"""
        # Puertos comúnmente explotados
        suspicious_ports = [22, 23, 80, 443, 1883, 8883]
        
        if TCP in packet:
            dst_port = packet[TCP].dport
            if dst_port in suspicious_ports:
                # Verificar si es tráfico interno esperado
                if not self.is_expected_traffic(src_ip, dst_ip, dst_port):
                    return True
        return False

    def is_expected_traffic(self, src_ip, dst_ip, port):
        """Verifica si el tráfico es esperado"""
        expected_patterns = [
            # Patrones de tráfico normal
        ]
        return any(pattern for pattern in expected_patterns)

    def detect_new_devices(self):
        """Escanea la red en busca de nuevos dispositivos"""
        while True:
            try:
                # Simular descubrimiento de dispositivos
                current_devices = self.scan_network()
                new_devices = current_devices - self.known_macs
                
                if new_devices:
                    for device in new_devices:
                        alert_msg = f"New device detected: {device}"
                        self.security_system.logger.warning(alert_msg)
                        self.security_system.suspicious_activities.append({
                            'timestamp': datetime.now().isoformat(),
                            'type': 'new_device',
                            'device_mac': device
                        })
                
                self.known_macs = current_devices
                time.sleep(300)  # Escanear cada 5 minutos
            except Exception as e:
                self.security_system.logger.error(f"Device detection error: {e}")

    def scan_network(self):
        """Simula escaneo de red (implementación básica)"""
        # En una implementación real, usaría arp-scan o similar
        return set(["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"])

    def analyze_bandwidth(self):
        """Analiza el uso de ancho de banda"""
        while True:
            try:
                stats = psutil.net_io_counters()
                current_usage = stats.bytes_sent + stats.bytes_recv
                
                if hasattr(self, 'last_usage'):
                    usage_change = current_usage - self.last_usage
                    if usage_change > 1000000:  # 1MB threshold
                        alert_msg = f"High bandwidth usage detected: {usage_change} bytes"
                        self.security_system.logger.warning(alert_msg)
                
                self.last_usage = current_usage
                time.sleep(60)  # Verificar cada minuto
            except Exception as e:
                self.security_system.logger.error(f"Bandwidth analysis error: {e}")

class FirmwareValidator:
    def __init__(self, security_system):
        self.security_system = security_system
        self.valid_signatures = set()

    def verify_firmware_integrity(self, firmware_path, expected_hash):
        """Verifica la integridad del firmware usando hash SHA-256"""
        try:
            file_hash = self.calculate_file_hash(firmware_path)
            
            if file_hash == expected_hash:
                self.security_system.logger.info("Firmware integrity verified")
                return True
            else:
                alert_msg = f"Firmware integrity compromised. Expected: {expected_hash}, Got: {file_hash}"
                self.security_system.logger.error(alert_msg)
                return False
        except Exception as e:
            self.security_system.logger.error(f"Firmware verification error: {e}")
            return False

    def calculate_file_hash(self, file_path):
        """Calcula hash SHA-256 de un archivo"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def verify_digital_signature(self, firmware_data, signature, public_key):
        """Verifica firma digital del firmware"""
        # Implementación simplificada - en producción usar cryptography
        try:
            # Simular verificación de firma
            is_valid = self.mock_signature_verification(firmware_data, signature, public_key)
            return is_valid
        except Exception as e:
            self.security_system.logger.error(f"Signature verification error: {e}")
            return False

    def mock_signature_verification(self, data, signature, public_key):
        """Simulación de verificación de firma (reemplazar en producción)"""
        return len(signature) > 0  # Simulación básica

class DeviceAuthenticator:
    def __init__(self, security_system):
        self.security_system = security_system
        self.device_tokens = {}

    def generate_device_token(self, device_id):
        """Genera token de autenticación para dispositivo"""
        timestamp = str(int(time.time()))
        message = f"{device_id}:{timestamp}"
        secret_key = b"iot_auth_secret_2024"
        
        token = hmac.new(secret_key, message.encode(), hashlib.sha256).hexdigest()
        self.device_tokens[device_id] = {
            'token': token,
            'timestamp': timestamp,
            'expires': int(time.time()) + 3600  # 1 hora
        }
        
        return token

    def verify_device_token(self, device_id, token):
        """Verifica token de dispositivo"""
        if device_id not in self.device_tokens:
            return False
        
        stored_token = self.device_tokens[device_id]
        
        # Verificar expiración
        if time.time() > stored_token['expires']:
            del self.device_tokens[device_id]
            return False
        
        # Verificar token
        if stored_token['token'] == token:
            return True
        
        return False

    def authenticate_device(self, device_id, credentials):
        """Autentica dispositivo usando credenciales"""
        # Implementar lógica de autenticación robusta
        expected_credentials = self.get_expected_credentials(device_id)
        
        if credentials == expected_credentials:
            token = self.generate_device_token(device_id)
            self.security_system.logger.info(f"Device {device_id} authenticated successfully")
            return token
        else:
            self.security_system.logger.warning(f"Failed authentication attempt for device {device_id}")
            return None

    def get_expected_credentials(self, device_id):
        """Obtiene credenciales esperadas para el dispositivo"""
        # En producción, obtener de base de datos segura
        return f"secure_cred_{device_id}"

class SecurityAlertSystem:
    def __init__(self, security_system):
        self.security_system = security_system
        self.alert_threshold = 5  # Número de alertas para acción automática

    def log_security_event(self, event_type, description, severity="MEDIUM"):
        """Registra evento de seguridad"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'description': description,
            'severity': severity
        }
        
        self.security_system.suspicious_activities.append(event)
        
        # Log según severidad
        if severity == "HIGH":
            self.security_system.logger.error(f"SECURITY ALERT: {description}")
        elif severity == "MEDIUM":
            self.security_system.logger.warning(f"Security warning: {description}")
        else:
            self.security_system.logger.info(f"Security event: {description}")

    def analyze_incidents(self):
        """Analiza incidentes y toma acciones automáticas"""
        high_severity_count = sum(1 for event in self.security_system.suspicious_activities 
                                if event['severity'] == "HIGH")
        
        if high_severity_count >= self.alert_threshold:
            self.trigger_automatic_response()

    def trigger_automatic_response(self):
        """Ejecuta respuesta automática a incidentes"""
        self.security_system.logger.critical("Multiple high severity alerts - triggering automatic response")
        
        # Acciones automáticas
        actions = [
            "Blocking suspicious IP addresses",
            "Isolating compromised devices",
            "Increasing monitoring frequency",
            "Notifying security team"
        ]
        
        for action in actions:
            self.security_system.logger.info(f"Automatic response: {action}")
            time.sleep(1)

def main():
    """Función principal del sistema de seguridad IoT"""
    print("Iniciando Sistema de Seguridad IoT - SmartLife Solutions")
    
    # Inicializar sistema
    security_system = IoTSecuritySystem()
    network_monitor = NetworkMonitor(security_system)
    firmware_validator = FirmwareValidator(security_system)
    device_authenticator = DeviceAuthenticator(security_system)
    alert_system = SecurityAlertSystem(security_system)
    
    # Iniciar monitoreo
    network_monitor.start_monitoring()
    
    # Ejemplos de uso
    try:
        # Simular autenticación de dispositivo
        device_id = "sensor_motion_001"
        token = device_authenticator.authenticate_device(device_id, "secure_cred_sensor_motion_001")
        
        if token:
            print(f"Dispositivo autenticado. Token: {token}")
        
        # Simular cifrado de datos
        sensor_data = {
            "device_id": device_id,
            "timestamp": datetime.now().isoformat(),
            "motion_detected": True,
            "temperature": 23.5
        }
        
        encrypted_data = security_system.encrypt_data(sensor_data)
        print(f"Datos cifrados: {encrypted_data}")
        
        # Mantener el sistema ejecutándose
        while True:
            time.sleep(10)
            alert_system.analyze_incidents()
            
    except KeyboardInterrupt:
        print("\nDeteniendo sistema de seguridad...")
    except Exception as e:
        security_system.logger.error(f"Error en sistema principal: {e}")

if __name__ == "__main__":
    main()