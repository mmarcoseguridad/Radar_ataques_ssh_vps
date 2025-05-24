# Radar_ataques_ssh_vps
Codigo fuente de una aplicacion  que detectea ataques ssh en un vps  con python

Esta aplicación:

Analiza los logs de autenticación en busca de intentos fallidos de SSH
Detecta patrones de ataque basados en un umbral configurable
Puede bloquear IPs atacantes usando iptables
Permite configurar una lista blanca de IPs permitidas
Puede enviar notificaciones por correo electrónico
Puede ejecutarse como demonio en segundo plano

Guarda el código en un archivo, por ejemplo ssh_attack_detector.py
Dale permisos de ejecución: chmod +x ssh_attack_detector.py
Ejecútalo con privilegios de superusuario (necesario para bloquear IPs):

# Uso básico
sudo python3 ssh_attack_detector.py

# Especificar archivo de log diferente
sudo python3 ssh_attack_detector.py --log /var/log/secure

# Bloquear IPs atacantes automáticamente
sudo python3 ssh_attack_detector.py --block

# Ejecutar como demonio, verificando cada 10 minutos
sudo python3 ssh_attack_detector.py --daemon --interval 600 --block

# Con notificación por correo
sudo python3 ssh_attack_detector.py --notify --email-sender tu@email.com --email-recipient admin@email.com --email-password tupassword --smtp-server smtp.gmail.com

