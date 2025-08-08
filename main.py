from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib import RR, QTYPE, A, SOA, TXT
import random
import time
from datetime import datetime, UTC
import os
import sys

# 📁 Ruta de logs (puede venir de variable de entorno)
# Opción 1: Usar directorio relativo al script
#LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
# Opción 2: Si prefieres ruta absoluta, descomenta la línea siguiente:
LOG_DIR = "./logs"
LOG_FILE = os.path.join(LOG_DIR, "dns_honeypot.log")

# Crear directorio de logs con manejo de errores mejorado
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    # Verificar que podemos escribir en el directorio
    test_file = os.path.join(LOG_DIR, "test_write.tmp")
    with open(test_file, "w") as f:
        f.write("test")
    os.remove(test_file)
    print(f"[+] Directorio de logs creado/verificado: {LOG_DIR}")
except PermissionError:
    print(f"[!] Error: Sin permisos para escribir en {LOG_DIR}")
    print("[!] Intentando usar directorio local...")
    LOG_DIR = "./logs"
    LOG_FILE = os.path.join(LOG_DIR, "dns_honeypot.log")
    os.makedirs(LOG_DIR, exist_ok=True)
    print(f"[+] Usando directorio local: {LOG_DIR}")
except Exception as e:
    print(f"[!] Error al crear directorio de logs: {e}")
    sys.exit(1)

# Zona falsa para simular transferencia
FAKE_ZONE = {
    "admin.example.com.": "192.0.2.1",
    "mail.example.com.": "192.0.2.2",
    "vpn.example.com.": "192.0.2.3",
    "dev.example.com.": "192.0.2.4",
    "secret.example.com.": "192.0.2.5"
}

class TrollResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        ip = handler.client_address[0]

        # Log de consulta con mejor manejo de errores
        log_entry = f"{datetime.now(UTC).isoformat()} | {ip} | dns | {qtype} | {qname}\n"

        try:
            with open(LOG_FILE, "a", encoding='utf-8') as log:
                log.write(log_entry)
                log.flush()  # Forzar escritura inmediata
            print(f"[LOG] {log_entry.strip()}")  # También mostrar en consola
        except Exception as e:
            print(f"[!] Error al escribir log: {e}")
            print(f"[!] Entrada que se intentó escribir: {log_entry.strip()}")
            # Intentar escribir en un archivo de backup
            try:
                backup_file = "./dns_honeypot_backup.log"
                with open(backup_file, "a", encoding='utf-8') as backup:
                    backup.write(log_entry)
                    backup.flush()
                print(f"[+] Log guardado en archivo de backup: {backup_file}")
            except:
                print("[!] No se pudo escribir ni en el archivo principal ni en el backup")

        reply = request.reply()

        if qtype == "AXFR":
            # Simula transferencia de zona (fake AXFR)
            print(f"[ALERT] Intento de transferencia de zona AXFR desde {ip}")
            for fqdn, fake_ip in FAKE_ZONE.items():
                reply.add_answer(RR(fqdn, QTYPE.A, rdata=A(fake_ip), ttl=300))
            reply.add_answer(RR(qname, QTYPE.SOA, ttl=300,
                rdata=SOA("ns.fakehost.com.", "admin.fakehost.com.",
                          (2025080101, 3600, 1800, 604800, 86400))))
            return reply

        if qtype == "A":
            fake_ip = f"{random.randint(100,255)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(fake_ip), ttl=60))

        elif qtype == "TXT":
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("Access Denied"), ttl=60))

        return reply

def test_logging():
    """Función para probar que el logging funciona"""
    test_entry = f"{datetime.now(UTC).isoformat()} | TEST | dns | A | test.example.com.\n"
    try:
        with open(LOG_FILE, "a", encoding='utf-8') as log:
            log.write(test_entry)
            log.flush()
        print(f"[+] Test de logging exitoso: {LOG_FILE}")
        return True
    except Exception as e:
        print(f"[!] Test de logging falló: {e}")
        return False

banner = """
⠀⠀⠀⠀⠀⠀⠀⢀⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣀⠀⠀⠀⠀⢀⣾⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⣧⡀⠀⠀⣼⠃⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⠻⣷⣄⡀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣧⠀⠀⠀⠀⠀⢀⣴⡶⠀⠀⠀⠀⠀
⠀⢸⣿⣧⠀⣰⡏⠀⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣠⣤⣈⣧⠈⠻⣿⣦⣀⣀⠀⠀⠀⣸⣿⣿⣿⣆⠀⠀⠀⣴⣿⣿⠃⠀⠀⠀⠀⠀
⠀⠘⡏⢿⣧⣿⠀⢀⣿⠁⠀⢀⣾⡇⠀⠀⠀⣀⠤⠖⠂⠉⠉⠀⠀⠀⠀⠀⠸⡏⣀⣀⣭⣷⣄⠉⠉⠒⢻⣿⣿⣿⣿⡆⢀⣾⣿⣿⡏⠀⠀⠀⠀⠀⠀
⠀⣤⣇⠘⣿⠇⠀⢸⡇⠀⢠⣾⣿⣀⡤⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⢻⣽⣿⣿⣿⣧⡀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⢸⣿⣿⡀⢻⡇⢠⡿⠀⣰⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣷⡀⢸⣿⣿⣿⣿⠏⠙⢿⣿⣿⣇⠀⠀⠀⠀⢀⣶
⢸⣿⣿⣧⣈⣧⡿⠁⢠⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣧⠈⣿⣿⣿⡏⠀⠀⣼⢹⣿⣿⠀⠀⠀⢀⣾⣿
⣿⡟⢿⣿⣿⣿⠁⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⠳⡀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⡆⢹⣿⣿⠁⠀⢀⢛⣼⣿⣿⠳⣄⢀⣾⣿⣿
⢻⡇⠀⢻⣿⣇⡞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⠘⢦⣀⡀⠀⠀⠈⠻⣿⣿⣿⣇⠀⣿⡟⠀⠀⡞⣿⣿⣿⣿⠀⠘⣿⡗⣿⣿
⠈⣧⠀⠈⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⡀⠈⠙⡓⠶⣤⣄⡈⠻⣿⣿⣧⣸⡇⡆⠀⢳⣿⣿⣿⡇⠀⣸⣏⠁⣿⣿
⠀⠹⡆⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠉⠳⢦⡈⠛⠷⣿⣿⣿⣿⣅⠁⠀⣿⣿⣿⡟⠀⢰⣿⠃⠀⣼⣿
⠀⠀⢻⣀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠲⣄⣄⣌⣲⣄⠸⣿⡿⣿⣿⣷⣴⣿⣿⠟⠀⠀⣿⡿⠀⠀⣸⡟
⠀⠀⠘⣿⡏⠀⠀⠀⢀⠀⠀⠀⠀⠀⠐⣿⣿⢿⣶⣶⣦⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣿⣿⣷⣿⣧⠈⠻⢿⣿⣿⠋⠀⠀⢸⣿⠇⠀⣼⡿⣇
⠀⣀⡴⢋⣴⣿⣿⣿⣿⣿⡷⠿⣿⣿⣿⢣⣾⣿⣿⣿⣿⣷⣭⣙⠶⡄⠀⠀⢰⡇⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣧⠀⠘⠛⣿⣆⠀⠀⣿⡇⠀⢀⣿⠇⢸
⠀⢻⠀⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠈⢁⣾⣿⣿⣿⣿⣿⣿⣿⣿⣷⡹⡄⠀⠀⠳⡄⠀⠀⠀⠀⠀⠀⠈⠙⠿⣿⣇⠀⠀⠈⢻⡆⢸⠃⠀⠀⣾⠏⠀⢸
⠀⠈⡇⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡹⡀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣾⡄⠀⠀⢿⡟⠀⣠⣼⣿⠇⠀⢼
⠀⠸⣅⢷⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⡇⠀⠀⢧⡀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣦⢠⣿⣿⣿⡿⣿⣿⠀⠀⡟
⠀⣀⡿⠈⢿⣿⣿⡇⢻⣿⡗⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⣸⠁⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⠿⠋⣴⣿⣿⠀⢀⡟
⠀⡿⠁⠀⠼⠛⢹⣯⣸⣿⣷⡄⠀⠀⠀⠀⠈⠻⢿⣿⣿⣿⡿⠛⠁⡰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠞⠉⢿⡿⠿⠟⣻⡟⠁⢠⡾⠛⢩⣿⣰⡿⠀
⠸⡇⠀⠀⠀⠀⢸⠇⠿⠋⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠜⠁⠀⠀⣠⡴⢻⣿⣿⣶⣶⣶⣾⡿⠀⡖⢸⡇⠀⢠⡟⣠⡾⣋⣴⣴⠟⣽⣿⠃⠀
⠀⢷⠀⢀⡾⣤⣼⣶⡖⠶⣿⠃⠀⠀⠀⠀⠀⢲⣷⣶⡶⠶⠆⣀⣀⣠⣴⠟⡟⠀⠀⠻⣿⣿⣿⣿⣿⠁⢨⠃⣸⣿⣦⣿⣟⣩⣾⡿⠋⣡⣾⣿⠃⠀⠀
⠀⠀⠉⠉⠀⢰⠏⠈⠻⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⣏⣴⣾⣿⡟⠁⠀⠀⣸⡇⠀⠀⠀⢿⠻⠿⢫⠏⠀⠀⠀⣿⣿⣿⣿⣿⠿⠁⣶⣴⣿⣿⠇⠀⠀⠀
⠀⠀⠀⠀⢀⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⣿⠏⣿⡇⠀⢀⣾⣿⠧⠀⠀⠀⢸⡄⣰⠟⠀⠀⠀⢠⣿⣿⣿⣯⣁⣠⣾⣿⣿⠟⠋⠀⠀⠀⠀
⠀⠀⠀⠀⣼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠘⠋⢰⣿⣿⣶⡾⣿⣿⠇⠀⣠⠞⢉⠜⠁⡴⠀⢀⣴⡟⠉⠀⠉⠛⠿⠿⠟⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣹⣶⡦⣴⢲⣴⢦⡤⣤⣤⣄⣤⣤⣤⣤⣤⣴⡿⠋⠙⢿⣯⣿⣿⠀⡰⠃⠀⠋⠀⡼⠁⠀⡞⣸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⡏⣿⢰⡇⢰⠇⢸⡇⣸⣨⣇⣸⣏⣸⢇⣾⣿⣀⣠⠤⠤⠵⣫⠏⠀⠀⠀⠀⠀⠀⠀⠀⡼⠀⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠙⣟⢿⢿⣿⣷⣿⣹⣇⣿⣸⣧⠥⠿⠴⠜⠋⠁⠀⠀⡴⠞⠁⠀⠀⠀⠀⠀⠀⠀⢀⡴⠁⢀⣼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⠛⠉⠉⠙⠉⠁⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢀⣠⣾⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⣠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣴⣶⠾⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣸⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣾⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⢀⣠⣾⡾⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⠀⢀⣀⡀⣀⡀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⠶⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⢷⣂⣀⣀⣀⣍⣳⣶⣾⣿⠿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠛⠻⠿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

if __name__ == "__main__":
    os.system("clear")
    time.sleep(1)
    # Imprimir banner
    print("")
    print(banner)
    print("[+] Iniciando DNS Honeypot...")
    print(f"[+] Archivo de log: {LOG_FILE}")

    # Probar logging antes de iniciar el servidor
    if not test_logging():
        print("[!] No se puede escribir en el archivo de logs. Abortando...")
        sys.exit(1)

    resolver = TrollResolver()
    logger = DNSLogger(prefix=False)

    try:
        udp_server = DNSServer(resolver, port=53, address="0.0.0.0", logger=logger)
        tcp_server = DNSServer(resolver, port=53, address="0.0.0.0", logger=logger, tcp=True)

        print("[+] DNS honeypot with AXFR running on UDP/TCP port 53")
        print(f"[+] Logs se guardarán en: {LOG_FILE}")

        udp_server.start_thread()
        tcp_server.start_thread()

        print("[+] Servidores iniciados. Presiona Ctrl+C para detener...")

        while True:
            time.sleep(1)

    except PermissionError:
        print("[!] Error: Sin permisos para bind al puerto 53")
        print("[!] Ejecuta como root o usa un puerto > 1024")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping DNS honeypot...")
    except Exception as e:
        print(f"[!] Error inesperado: {e}")
        sys.exit(1)
