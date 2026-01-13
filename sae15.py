import tkinter as tk
from tkinter import filedialog, messagebox
import re
import csv
import pandas as pd
import matplotlib.pyplot as plt
import markdown
import webbrowser
import os

#configuration
PORT_MAP = {
    '80': 'HTTP', '443': 'HTTPS', '8080': 'HTTP-ALT',
    '20': 'FTP-DATA', '21': 'FTP',
    '22': 'SSH', '23': 'TELNET',
    '25': 'SMTP', '53': 'DNS',
    '110': 'POP3', '143': 'IMAP',
    '3306': 'MySQL', '3389': 'RDP',
    '445': 'SMB', '139': 'NetBIOS',
    '1900': 'SSDP', '67': 'DHCP', '68': 'DHCP'
}

INSECURE_PROTOCOLS = ['TELNET', 'FTP', 'HTTP', 'POP3', 'VNC']

FLAG_MEANINGS = {
    'S': 'Initialisation (SYN)\n-> Tentative de connexion',
    'S.': 'Syn-Ack\n-> Réponse du serveur',
    '.': 'Accusé (ACK)\n-> Trafic normal',
    'P.': 'Données (PSH)\n-> Transfert d\'infos',
    'F.': 'Fin (FIN)\n-> Clôture propre',
    'R': 'Rejet (RST)\n-> Connexion refusée',
    'Req': 'Requête (ARP)',
    'Rep': 'Réponse (ARP)'
}


def get_protocol_name(port_str, info_line=""):
    """Détermine le nom du protocole en fonction du port ou du contenu de la ligne."""
    info_line = info_line.upper()
    port_str = str(port_str).upper()

    if "ARP" in info_line or port_str == "ARP": return "ARP"
    if "STP" in info_line or "802.1W" in info_line: return "STP"
    if "HSRP" in info_line: return "HSRP"
    if "BOOTP" in info_line or "DHCP" in info_line: return "DHCP"
    if "NETBIOS" in port_str or "NETBIOS" in info_line: return "NETBIOS"
    if "SSDP" in info_line: return "SSDP"

    explicit_proto = re.search(r':\s+([A-Z]{3,10})$', info_line.strip())
    if explicit_proto:
        return explicit_proto.group(1)

    port_lower = port_str.lower()
    for p_name in ['http', 'ssh', 'dns', 'telnet', 'ftp', 'smtp', 'https', 'mysql', 'rdp', 'vnc']:
        if p_name in port_lower:
            return p_name.upper()

    if port_str.isdigit():
        return PORT_MAP.get(port_str, f"TCP/{port_str}")
    
    return port_str if port_str != "0" else "IP-General"

def parse_tcpdump(filepath):
    """Lit le fichier tcpdump en ignorant le bruit hexadécimal et les balises sources."""
    data = []
    
    #csv
    pattern_generic = re.compile(r'.*?(\d{2}:\d{2}:\d{2}\.\d+)\s+([A-Za-z0-9\.-]+)(?:,\s+|\s+)(.*)')
    pattern_flags = re.compile(r'Flags\s+\[([^\s\]]+)\]')

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith('0x') or len(line) < 15:
                    continue
                
                if line.startswith('[source'):
                    if ']' in line:
                        line = line.split(']', 1)[1].strip()
                    else:
                        continue 

                match = pattern_generic.search(line)
                if match:
                    timestamp, type_proto, info = match.groups()
                    
                    src_ip, src_port = "Inconnu", "0"
                    dst_ip, dst_port = "Broadcast", "0"
                    proto = "TCP"
                    flags = "N/A"

                    if type_proto == "IP":
                        if ' > ' in info:
                            parts = info.split(' > ')
                            src_full = parts[0].strip()
                            rest = parts[1]
                            
                            if ':' in rest:
                                dst_full, info_text = rest.split(':', 1)
                            else:
                                dst_full, info_text = rest, ""

                            s_parts = src_full.rsplit('.', 1)
                            src_ip, src_port = (s_parts[0], s_parts[1]) if len(s_parts) > 1 else (src_full, "0")

                            d_parts = dst_full.rsplit('.', 1)
                            dst_ip, dst_port = (d_parts[0], d_parts[1]) if len(d_parts) > 1 else (dst_full, "0")
                            
                            proto = get_protocol_name(dst_port, info_text)
                            
                            flag_match = pattern_flags.search(info_text)
                            if flag_match: flags = flag_match.group(1)
                        else:
                            continue 

                    elif type_proto == "ARP":
                        proto = "ARP"
                        if "who-has" in info:
                            try:
                                parts = info.split()
                                if "who-has" in parts and "tell" in parts:
                                    dst_ip = parts[parts.index("who-has") + 1]
                                    src_ip = parts[parts.index("tell") + 1].strip(',')
                                    flags = "Req"
                            except: pass
                        elif "is-at" in info:
                            flags = "Reply"
                            src_ip = "ARP-Reply"

                    elif type_proto == "STP":
                        proto = "STP"
                        src_ip = "Switch-Bridge"
                        dst_ip = "Multicast"

                    if src_ip == "Inconnu" and proto == "TCP":
                        continue

                    data.append({
                        "Heure": timestamp,
                        "Source": src_ip,
                        "Port_Source": src_port,
                        "Destination": dst_ip,
                        "Port_Dest": dst_port,
                        "Protocole": proto,
                        "Flags": flags
                    })
        return data
    except Exception as e:
        messagebox.showerror("Erreur", f"Lecture échouée : {e}")
        return []

#Risque
def analyze_security(df):
    alerts = []
    insecure = df[df['Protocole'].isin(INSECURE_PROTOCOLS)]
    if not insecure.empty:
        alerts.append(f"<li><b>ALERTE CONFIDENTIALITÉ :</b> {len(insecure)} paquets utilisent des protocoles non chiffrés ({', '.join(insecure['Protocole'].unique())}). Risque d'interception.</li>")

    syn_count = len(df[df['Flags'].astype(str).str.contains('S', na=False)])
    if syn_count > 50:
        alerts.append(f"<li><b>SUSPICION DE SCAN :</b> {syn_count} tentatives de connexions (SYN) détectées.</li>")

    rst_count = len(df[df['Flags'].astype(str).str.contains('R', na=False)])
    if rst_count > 20:
        alerts.append(f"<li><b>ANOMALIE FLUX :</b> {rst_count} connexions ont été brutalement rejetées (RST).</li>")

    arp_count = len(df[df['Protocole'] == 'ARP'])
    if arp_count > len(df) * 0.3:
        alerts.append(f"<li><b>ACTIVITÉ ARP ÉLEVÉE :</b> {arp_count} paquets ARP détectés. Vérifier la stabilité du réseau local.</li>")

    if not alerts:
        alerts.append("<li>Aucune menace immédiate détectée par le moteur d'analyse.</li>")

    return "<ul>" + "".join(alerts) + "</ul>"

def create_reports(csv_path, base_filename):
    try:
        df = pd.read_csv(csv_path, delimiter=';')

        plt.figure(figsize=(10, 5))
        if not df.empty:
            df['Source'].value_counts().head(7).plot(kind='pie', autopct='%1.1f%%', cmap='Pastel1')
        plt.title("Répartition des Sources")
        plt.tight_layout(); plt.savefig("sources.png"); plt.close()

        plt.figure(figsize=(12, 6))
        if not df.empty:
            flag_counts = df['Flags'].value_counts().head(8)
            labels = [FLAG_MEANINGS.get(x, x) for x in flag_counts.index]
            colors = ['#e74c3c' if 'S' in str(x) or 'R' in str(x) else '#3498db' for x in flag_counts.index]
            plt.bar(labels, flag_counts.values, color=colors)
        plt.title("Analyse du Comportement (Flags)"); plt.tight_layout()
        plt.savefig("flags.png"); plt.close()

        # Analyse des risques
        risk_html = analyze_security(df)

        # Markdown
        md_content = f"""
# Rapport Sécurité Réseau
**Fichier analysé :** `{base_filename}.txt`  
**Date du scan :** {pd.Timestamp.now().strftime('%d/%m/%Y %H:%M')}
**Total Paquets :** {len(df)}

---

## 1. Analyse des Risques et Alertes
{risk_html}

---

## 2. Visualisation des Flux

### A. Top Sources (Sources)
![Sources](sources.png)

### B. Nature des échanges (Flags)
![Flags](flags.png)

---

## 3. Registre Complet des Paquets
*Ce tableau contient l'intégralité des {len(df)} lignes de l'analyse.*

<div class="table-container">
{df.to_html(index=False, classes='table-style', border=0)}
</div>
"""

        md_filename = f"{base_filename}.md"
        with open(md_filename, "w", encoding="utf-8") as f:
            f.write(md_content)

        html_body = markdown.markdown(md_content, extensions=['tables'])
        html_final = f"""
        <html><head><meta charset="UTF-8">
        <style>
            @keyframes slideIn {{ from {{ opacity: 0; transform: translateY(20px); }} to {{ opacity: 1; transform: translateY(0); }} }}
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; padding: 40px; background: #eaeff2; }}
            .container {{ max-width: 1100px; margin: auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); animation: slideIn 0.5s ease-out; }}
            h1 {{ color: #2c3e50; border-bottom: 4px solid #3498db; padding-bottom: 15px; text-transform: uppercase; }}
            h2 {{ color: #2980b9; margin-top: 40px; padding-bottom: 10px; border-bottom: 1px solid #eee; }}
            ul {{ list-style: none; padding-left: 0; }}
            li {{ padding: 12px; margin-bottom: 8px; background: #fff; border-left: 5px solid #3498db; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: 0.3s; }}
            li:hover {{ transform: translateX(5px); background: #f9f9f9; }}
            img {{ max-width: 100%; height: auto; border-radius: 8px; margin: 20px 0; border: 1px solid #eee; transition: 0.3s; }}
            img:hover {{ transform: scale(1.01); box-shadow: 0 5px 15px rgba(0,0,0,0.1); }}
            .table-container {{ height: 600px; overflow-y: auto; border: 1px solid #ddd; border-radius: 8px; margin-top: 20px; }}
            .table-style {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
            .table-style th {{ background: #34495e; color: white; padding: 12px; position: sticky; top: 0; text-align: left; }}
            .table-style td {{ padding: 10px; border-bottom: 1px solid #eee; }}
            .table-style tr:nth-child(even) {{ background: #fcfcfc; }}
            .table-style tr:hover {{ background: #f1f7ff; }}
        </style></head>
        <body><div class="container">{html_body}</div></body></html>"""
        
        html_filename = f"{base_filename}.html"
        with open(html_filename, "w", encoding="utf-8") as f:
            f.write(html_final)
        
        return html_filename
    except Exception as e:
        messagebox.showerror("Erreur", str(e)); return None

#tkinter

def process_file():
    path = filedialog.askopenfilename(filetypes=[("Logs TCPDump", "*.txt"), ("Tous", "*.*")])
    if path:
        base_name = os.path.splitext(os.path.basename(path))[0]
        
        data = parse_tcpdump(path)
        if data:
            keys = data[0].keys()
            csv_file = f"{base_name}.csv"
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys, delimiter=';')
                writer.writeheader(); writer.writerows(data)
            
            result_html = create_reports(csv_file, base_name)
            if result_html:
                messagebox.showinfo("Succès", f"Rapports générés : {base_name}.csv, .md et .html")
                webbrowser.open('file://' + os.path.realpath(result_html))
        else:
            messagebox.showwarning("Attention", "Aucun paquet valide trouvé ou fichier vide.")

if __name__ == "__main__":
    root = tk.Tk()
    root.title("TCPDump Analyzer Pro")
    root.geometry("400x250")
    tk.Label(root, text="Analyseur de Risques Réseau", font=("Arial", 14, "bold")).pack(pady=40)
    tk.Button(root, text="Importer & Analyser", command=process_file, bg="#3498db", fg="white", font=("Arial", 11), height=2, width=25).pack()
    root.mainloop()