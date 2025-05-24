#!/usr/bin/env python3
import re
import os
import time
import smtplib
import argparse
import ipaddress
from email.mime.text import MIMEText
from collections import defaultdict, Counter
from datetime import datetime, timedelta

class SSHAttackDetector:
    def __init__(self, log_file="/var/log/auth.log", threshold=5, time_window=5,
                 whitelist=None, notify=False, email_config=None):
        self.log_file = log_file
        self.threshold = threshold  # Intentos fallidos para considerar ataque
        self.time_window = time_window  # Ventana de tiempo en minutos
        self.whitelist = whitelist or []
        self.notify = notify
        self.email_config = email_config
        self.failed_attempts = defaultdict(list)
        self.blocked_ips = set()

    def parse_log_file(self):
        """Analiza el archivo de log para detectar intentos fallidos de SSH"""
        if not os.path.exists(self.log_file):
            print(f"Error: El archivo {self.log_file} no existe")
            return False

        # Patrones para detectar intentos fallidos de SSH
        patterns = [
            r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
            r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)",
            r"Connection closed by authenticating user .* (\d+\.\d+\.\d+\.\d+)",
            r"Failed publickey for .* from (\d+\.\d+\.\d+\.\d+)"
        ]

        current_time = datetime.now()
        cutoff_time = current_time - timedelta(minutes=self.time_window)

        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    # Extraer timestamp de la línea de log
                    try:
                        log_time_str = " ".join(line.split()[:3])
                        log_time = datetime.strptime(f"{current_time.year} {log_time_str}", "%Y %b %d %H:%M:%S")

                        # Ajustar el año si la fecha parece estar en el futuro
                        if log_time > current_time and log_time.month == 12 and current_time.month == 1:
                            log_time = log_time.replace(year=current_time.year - 1)
                    except:
                        continue

                    # Ignorar entradas antiguas
                    if log_time < cutoff_time:
                        continue

                    # Buscar IPs en intentos fallidos
                    for pattern in patterns:
                        match = re.search(pattern, line)
                        if match:
                            ip = match.group(1)

                            # Ignorar IPs en la lista blanca
                            if ip in self.whitelist:
                                continue

                            self.failed_attempts[ip].append(log_time)
                            break

            return True
        except Exception as e:
            print(f"Error al leer el archivo de log: {e}")
            return False

    def detect_attacks(self):
        """Detecta ataques basados en el número de intentos fallidos"""
        attacks = {}

        for ip, attempts in self.failed_attempts.items():
            if len(attempts) >= self.threshold:
                attacks[ip] = len(attempts)

        return attacks

    def block_ip(self, ip):
        """Bloquea una IP usando iptables"""
        if ip in self.blocked_ips:
            return

        try:
            # Verificar que la IP sea válida
            ipaddress.ip_address(ip)

            # Bloquear la IP con iptables
            os.system(f"iptables -A INPUT -s {ip} -j DROP")
            print(f"IP bloqueada: {ip}")
            self.blocked_ips.add(ip)
        except Exception as e:
            print(f"Error al bloquear la IP {ip}: {e}")

    def send_notification(self, attacks):
        """Envía una notificación por correo electrónico"""
        if not self.email_config:
            return

        try:
            sender = self.email_config.get('sender')
            recipient = self.email_config.get('recipient')
            password = self.email_config.get('password')
            smtp_server = self.email_config.get('smtp_server')
            smtp_port = self.email_config.get('smtp_port', 587)

            if not all([sender, recipient, password, smtp_server]):
                print("Configuración de correo incompleta")
                return

            subject = f"Alerta de seguridad: Ataques SSH detectados en {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

            body = "Se han detectado los siguientes ataques SSH:\n\n"
            for ip, count in attacks.items():
                body += f"IP: {ip} - Intentos fallidos: {count}\n"

            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = sender
            msg['To'] = recipient

            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
            server.quit()

            print("Notificación enviada por correo electrónico")
        except Exception as e:
            print(f"Error al enviar la notificación: {e}")

    def run(self, block=False):
        """Ejecuta el detector de ataques"""
        print(f"Analizando {self.log_file} en busca de ataques SSH...")

        if not self.parse_log_file():
            return

        attacks = self.detect_attacks()

        if not attacks:
            print("No se detectaron ataques")
            return

        print(f"Se detectaron {len(attacks)} posibles ataques:")
        for ip, count in attacks.items():
            print(f"IP: {ip} - Intentos fallidos: {count}")

            if block:
                self.block_ip(ip)

        if self.notify and attacks:
            self.send_notification(attacks)

def main():
    parser = argparse.ArgumentParser(description='Detector de ataques SSH para VPS')
    parser.add_argument('--log', default='/var/log/auth.log', help='Ruta al archivo de log (default: /var/log/auth.log)')
    parser.add_argument('--threshold', type=int, default=5, help='Número de intentos fallidos para considerar ataque (default: 5)')
    parser.add_argument('--time-window', type=int, default=5, help='Ventana de tiempo en minutos (default: 5)')
    parser.add_argument('--whitelist', nargs='+', help='Lista de IPs permitidas')
    parser.add_argument('--block', action='store_true', help='Bloquear IPs atacantes')
    parser.add_argument('--notify', action='store_true', help='Enviar notificación por correo')
    parser.add_argument('--email-sender', help='Correo del remitente')
    parser.add_argument('--email-recipient', help='Correo del destinatario')
    parser.add_argument('--email-password', help='Contraseña del correo')
    parser.add_argument('--smtp-server', help='Servidor SMTP')
    parser.add_argument('--smtp-port', type=int, default=587, help='Puerto SMTP (default: 587)')
    parser.add_argument('--daemon', action='store_true', help='Ejecutar como demonio')
    parser.add_argument('--interval', type=int, default=300, help='Intervalo de ejecución en segundos (default: 300)')

    args = parser.parse_args()

    email_config = None
    if args.notify:
        email_config = {
            'sender': args.email_sender,
            'recipient': args.email_recipient,
            'password': args.email_password,
            'smtp_server': args.smtp_server,
            'smtp_port': args.smtp_port
        }

    detector = SSHAttackDetector(
        log_file=args.log,
        threshold=args.threshold,
        time_window=args.time_window,
        whitelist=args.whitelist,
        notify=args.notify,
        email_config=email_config
    )

    if args.daemon:
        print(f"Ejecutando en modo demonio, intervalo: {args.interval} segundos")
        try:
            while True:
                detector.run(block=args.block)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Detector detenido")
    else:
        detector.run(block=args.block)

if __name__ == "__main__":
    main()
