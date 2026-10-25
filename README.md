# 🛡️ Network Auditing Toolkit (ARP + DNS Proxy Lab)

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-g.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

Una herramienta educativa de ciberseguridad desarrollada en Python para analizar e ilustrar el funcionamiento de los ataques **Man-in-the-Middle (MitM)** mediante **envenenamiento ARP (ARP Spoofing)**, **intercepción de tráfico DNS** y **servidor web local de auditoría** en entornos de laboratorio aislados.

---

## Aviso Legal / Disclaimer
Este software ha sido desarrollado **exclusivamente con fines educativos, de investigación y auditoría de seguridad en entornos de laboratorio autorizados**. 
* No debe ser utilizado en redes de producción ni en infraestructuras sin la autorización explícita por escrito del propietario.
* El autor no se hace responsable del uso indebido o daños causados por el uso de este software.

---

## Características Principales

* **ARP Spoofing Multihilo:** Ejecución pasiva e ininterrumpida mediante hilos (`threading`) y la librería `Scapy` para redirigir el tráfico entre la víctima y el gateway.
* **DNS Proxy Dinámico (Puerto 53):** Socket UDP local que intercepta consultas DNS específicas y redirige los dominios seleccionados mientras actúa como proxy transparente para el resto del tráfico legítimo.
* **Servidor Web Integrado (Puerto 80):** Servidor HTTP local embebido para validar de forma visual e inmediata el resultado de la redirección.
* **Gestión Automatizada de `iptables`:** Redirección automática del puerto 53 UDP del sistema al puerto del proxy y limpieza automatizada de reglas al finalizar mediante señales (`SIGINT`).

---

## Requisitos del Sistema

* **Sistema Operativo:** Linux (Probado y optimizado en Kali Linux / Debian).
* **Python:** 3.8 o superior.
* **Privilegios:** Requiere permisos de superusuario (`root` / `sudo`) para la manipulación de sockets raw y reglas de `iptables`.

### Dependencias de Python
* `scapy`

---

## Instalación

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/Destiny752/arp-dns-audit-suite.git
   cd arp-dns-audit-suite
