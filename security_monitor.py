import psutil
import time
import os
import sys
import tabulate
import socket
import datetime
import pandas as pd
import matplotlib.pyplot as plt
import logging
from collections import defaultdict
import hashlib
import winreg
import csv
import threading
import queue

# pip3 install psutil tabulate pandas matplotlib

# Log dosyasını yapılandır
logging.basicConfig(
    filename='security_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Veritabanı olarak kullanılacak CSV dosyaları
PROCESS_HISTORY_FILE = "process_history.csv"
NETWORK_HISTORY_FILE = "network_history.csv"
ALERTS_FILE = "security_alerts.csv"

# Şüpheli süreçler için bilinen kötü amaçlı yazılım isimleri
SUSPICIOUS_PROCESS_NAMES = [
    "cmd.exe", "powershell.exe", "netcat", "ncat", "nc.exe", "nmap", "psexec",
    "mimikatz", "rawreg", "reg.exe", "regedit.exe", "regsvr32.exe", "bitsadmin",
    "certutil.exe", "wireshark", "tcpdump", "taskschd.exe", "schtasks.exe"
]

# Şüpheli ağ bağlantı noktaları
SUSPICIOUS_PORTS = [
    22, 23, 25, 3389, 4444, 5900, 8080, 1080, 6667, 1337, 31337, 31338, 31339, 8443
]

class SecurityMonitor:
    def __init__(self):
        """Güvenlik izleme sistemini başlatır"""
        self.baseline_processes = {}
        self.baseline_connections = {}
        self.process_history = {}
        self.network_history = {}
        self.alert_queue = queue.Queue()
        
        # CSV dosyalarını oluştur/yükle
        self._init_csv_files()
        
        # Başlangıç veri analizi
        self.process_cpu_history = defaultdict(list)
        self.process_memory_history = defaultdict(list)
        self.process_disk_history = defaultdict(list)
        self.process_network_history = defaultdict(list)
        
        # Süreç izleme durumu
        self.monitoring = False
    
    def _init_csv_files(self):
        """CSV dosyalarını oluştur veya yükle"""
        # Süreç geçmişi
        if not os.path.exists(PROCESS_HISTORY_FILE):
            with open(PROCESS_HISTORY_FILE, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['timestamp', 'pid', 'name', 'exe', 'cmdline', 'username', 'cpu_percent', 'memory_percent'])
        
        # Ağ geçmişi
        if not os.path.exists(NETWORK_HISTORY_FILE):
            with open(NETWORK_HISTORY_FILE, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['timestamp', 'pid', 'process_name', 'local_addr', 'local_port', 'remote_addr', 'remote_port', 'status'])
        
        # Uyarılar
        if not os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['timestamp', 'alert_type', 'process_name', 'pid', 'details', 'severity'])
    
    def establish_baseline(self, duration=30):
        """
        Sistem için temel çalışma durumunu belirler
        
        :param duration: Baseline oluşturmak için izleme süresi (saniye)
        """
        print(f"Sistem baseline'ı oluşturuluyor... ({duration} saniye)")
        logging.info("Sistem baseline izlemesi başlatıldı")
        
        # Süreç ve bağlantı izleme
        start_time = time.time()
        while time.time() - start_time < duration:
            # Süreçleri izle
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    
                    if pid not in self.baseline_processes:
                        self.baseline_processes[pid] = {
                            'name': proc_info['name'],
                            'exe': proc_info['exe'],
                            'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                            'username': proc_info['username'],
                            'cpu_samples': [],
                            'memory_samples': []
                        }
                    
                    # CPU ve bellek örnekleri topla
                    self.baseline_processes[pid]['cpu_samples'].append(proc_info['cpu_percent'])
                    self.baseline_processes[pid]['memory_samples'].append(proc_info['memory_percent'])
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Ağ bağlantılarını izle
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.laddr and conn.raddr:
                        key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                        
                        if key not in self.baseline_connections:
                            self.baseline_connections[key] = {
                                'pid': conn.pid,
                                'status': conn.status,
                                'count': 0
                            }
                        
                        self.baseline_connections[key]['count'] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            time.sleep(1)
        
        # Baseline analizi
        for pid, data in self.baseline_processes.items():
            if data['cpu_samples']:
                data['avg_cpu'] = sum(data['cpu_samples']) / len(data['cpu_samples'])
                data['max_cpu'] = max(data['cpu_samples'])
                data['cpu_threshold'] = data['max_cpu'] * 1.5  # %50 tolerans
            
            if data['memory_samples']:
                data['avg_memory'] = sum(data['memory_samples']) / len(data['memory_samples'])
                data['max_memory'] = max(data['memory_samples'])
                data['memory_threshold'] = data['max_memory'] * 1.5  # %50 tolerans
            
            # Temizlik
            del data['cpu_samples']
            del data['memory_samples']
        
        print(f"Baseline oluşturuldu: {len(self.baseline_processes)} süreç ve {len(self.baseline_connections)} ağ bağlantısı izlendi")
        logging.info(f"Baseline oluşturuldu: {len(self.baseline_processes)} süreç ve {len(self.baseline_connections)} ağ bağlantısı")
    
    def _calculate_file_hash(self, file_path):
        """Dosya hash değerini hesaplar (MD5)"""
        try:
            if not os.path.exists(file_path):
                return "Dosya bulunamadı"
            
            md5_hash = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except Exception as e:
            return f"Hash hesaplanamadı: {str(e)}"
    
    def check_autorun_entries(self):
        """Windows'ta otomatik çalıştırılan programları kontrol eder"""
        autoruns = []
        try:
            # Başlangıç dizini kontrol et
            startup_dir = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            if os.path.exists(startup_dir):
                for item in os.listdir(startup_dir):
                    file_path = os.path.join(startup_dir, item)
                    file_hash = self._calculate_file_hash(file_path)
                    autoruns.append({
                        'type': 'Startup Folder',
                        'name': item,
                        'path': file_path,
                        'hash': file_hash
                    })
            
            # Registry Run anahtarlarını kontrol et
            registry_locations = [
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
            ]
            
            for hkey, key_path in registry_locations:
                try:
                    key = winreg.OpenKey(hkey, key_path)
                    try:
                        i = 0
                        while True:
                            name, value, _ = winreg.EnumValue(key, i)
                            autoruns.append({
                                'type': 'Registry',
                                'location': key_path,
                                'name': name,
                                'command': value
                            })
                            i += 1
                    except WindowsError:
                        pass
                    finally:
                        winreg.CloseKey(key)
                except WindowsError:
                    pass
        
        except Exception as e:
            logging.error(f"Autorun kontrol hatası: {str(e)}")
        
        return autoruns
    
    def _is_suspicious_process(self, proc_info):
        """Bir sürecin şüpheli olup olmadığını kontrol eder"""
        try:
            # İsim kontrolü
            if proc_info['name'].lower() in [p.lower() for p in SUSPICIOUS_PROCESS_NAMES]:
                return True, f"Şüpheli süreç ismi: {proc_info['name']}"
            
            # Komut satırı kontrolü (powershell veya cmd ile zararlı komutlar)
            if proc_info['cmdline']:
                cmd = proc_info['cmdline'].lower()
                suspicious_commands = ["download", "http://", "https://", "-enc", "-encodedcommand", 
                                      "-hidden", "-w hidden", "bypass", "webclient", "invoke-expression"]
                
                for susp_cmd in suspicious_commands:
                    if susp_cmd in cmd and ("powershell" in proc_info['name'].lower() or "cmd" in proc_info['name'].lower()):
                        return True, f"Şüpheli komut: {susp_cmd} in {proc_info['name']}"
            
            # Kullanıcı kontrolü (SYSTEM olarak çalışan ve bilinen bir sistem süreci olmayan)
            if proc_info['username'] and "SYSTEM" in proc_info['username'].upper():
                system_processes = ["lsass.exe", "services.exe", "svchost.exe", "csrss.exe", "smss.exe", "winlogon.exe"]
                if proc_info['name'].lower() not in [p.lower() for p in system_processes]:
                    return True, f"SYSTEM kullanıcısı ile çalışan şüpheli süreç: {proc_info['name']}"
            
            # Yüksek kaynak kullanımı
            if pid in self.baseline_processes:
                if proc_info['cpu_percent'] > self.baseline_processes[pid].get('cpu_threshold', 90):
                    return True, f"Anormal CPU kullanımı: {proc_info['name']} ({proc_info['cpu_percent']:.2f}%)"
                
                if proc_info['memory_percent'] > self.baseline_processes[pid].get('memory_threshold', 90):
                    return True, f"Anormal bellek kullanımı: {proc_info['name']} ({proc_info['memory_percent']:.2f}%)"
        
        except Exception as e:
            logging.error(f"Süreç analiz hatası: {str(e)}")
        
        return False, ""
    
    def _is_suspicious_connection(self, connection):
        """Bir ağ bağlantısının şüpheli olup olmadığını kontrol eder"""
        try:
            # Şüpheli port kontrolü
            if connection.raddr and connection.raddr.port in SUSPICIOUS_PORTS:
                return True, f"Şüpheli porta bağlantı: {connection.raddr.port}"
            
            # Bilinmeyen süreç ile bağlantı
            try:
                process = psutil.Process(connection.pid)
                if process.name().lower() in [p.lower() for p in SUSPICIOUS_PROCESS_NAMES]:
                    return True, f"Şüpheli süreç ağ bağlantısı: {process.name()}"
            except psutil.NoSuchProcess:
                return True, "Bilinmeyen süreç tarafından ağ bağlantısı"
            
            # Yüksek sayıda bağlantı
            if connection.pid:
                connection_count = sum(1 for c in psutil.net_connections() if c.pid == connection.pid)
                if connection_count > 50:  # Yüksek bağlantı sayısı eşiği
                    return True, f"Yüksek bağlantı sayısı: {connection_count} bağlantı"
            
            # Kritik IP adresleri (örnek: bilinmeyen yabancı IP'ler)
            if connection.raddr:
                # Şüpheli IP kontrolü yapılabilir
                pass
        
        except Exception as e:
            logging.error(f"Bağlantı analiz hatası: {str(e)}")
        
        return False, ""
    
    def analyze_process(self, proc_info, pid):
        """Bir süreci analiz eder ve anomalileri tespit eder"""
        is_suspicious, reason = self._is_suspicious_process(proc_info)
        
        if is_suspicious:
            # Uyarı kaydedilir
            self._log_alert("suspicious_process", proc_info['name'], pid, reason, "Medium")
            return True
        
        # Süreç geçmişi için veri kaydet
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # CSV'ye kaydet
        with open(PROCESS_HISTORY_FILE, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                pid,
                proc_info['name'],
                proc_info.get('exe', ''),
                proc_info.get('cmdline', ''),
                proc_info.get('username', ''),
                proc_info.get('cpu_percent', 0),
                proc_info.get('memory_percent', 0)
            ])
        
        # İzleme geçmişi için veri toplama
        self.process_cpu_history[pid].append(proc_info.get('cpu_percent', 0))
        self.process_memory_history[pid].append(proc_info.get('memory_percent', 0))
        
        # Uzun geçmişi önlemek için son 100 örneği tut
        if len(self.process_cpu_history[pid]) > 100:
            self.process_cpu_history[pid] = self.process_cpu_history[pid][-100:]
        if len(self.process_memory_history[pid]) > 100:
            self.process_memory_history[pid] = self.process_memory_history[pid][-100:]
        
        return False
    
    def analyze_network_connection(self, connection):
        """Bir ağ bağlantısını analiz eder ve anomalileri tespit eder"""
        is_suspicious, reason = self._is_suspicious_connection(connection)
        
        if is_suspicious:
            try:
                process_name = psutil.Process(connection.pid).name() if connection.pid else "Unknown"
                # Uyarı kaydedilir
                self._log_alert("suspicious_network", process_name, connection.pid, reason, "High")
                return True
            except psutil.NoSuchProcess:
                pass
        
        # Ağ geçmişi için veri kaydet
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Süreç adını al
        process_name = "Unknown"
        if connection.pid:
            try:
                process_name = psutil.Process(connection.pid).name()
            except psutil.NoSuchProcess:
                pass
        
        # Bağlantı bilgilerini hazırla
        local_addr = f"{connection.laddr.ip}:{connection.laddr.port}" if connection.laddr else "N/A"
        remote_addr = f"{connection.raddr.ip}" if connection.raddr else "N/A"
        remote_port = connection.raddr.port if connection.raddr else 0
        
        # CSV'ye kaydet
        with open(NETWORK_HISTORY_FILE, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                connection.pid if connection.pid else 0,
                process_name,
                connection.laddr.ip if connection.laddr else "N/A",
                connection.laddr.port if connection.laddr else 0,
                connection.raddr.ip if connection.raddr else "N/A",
                connection.raddr.port if connection.raddr else 0,
                connection.status
            ])
        
        return False
    
    def _log_alert(self, alert_type, process_name, pid, details, severity):
        """Güvenlik uyarısını kaydeder"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log dosyasına kaydet
        log_message = f"GÜVENLİK UYARISI: {alert_type} - {process_name} (PID: {pid}) - {details} - Önem: {severity}"
        if severity == "High":
            logging.critical(log_message)
        else:
            logging.warning(log_message)
        
        # CSV'ye kaydet
        with open(ALERTS_FILE, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                alert_type,
                process_name,
                pid,
                details,
                severity
            ])
        
        # Uyarı kuyruğuna ekle
        self.alert_queue.put({
            'timestamp': timestamp,
            'alert_type': alert_type,
            'process_name': process_name,
            'pid': pid,
            'details': details,
            'severity': severity
        })
    
    def monitor_processes(self, interval=1):
        """Süreçleri düzenli olarak izler"""
        while self.monitoring:
            try:
                # Tüm süreçleri kontrol et
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'cpu_percent', 'memory_percent']):
                    try:
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        # Süreci analiz et
                        self.analyze_process(proc_info, pid)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                time.sleep(interval)
            except Exception as e:
                logging.error(f"Süreç izleme hatası: {str(e)}")
                time.sleep(interval)
    
    def monitor_network(self, interval=2):
        """Ağ bağlantılarını düzenli olarak izler"""
        while self.monitoring:
            try:
                # Tüm ağ bağlantılarını kontrol et
                for connection in psutil.net_connections(kind='inet'):
                    try:
                        # Bağlantıyı analiz et
                        if connection.raddr:  # Sadece dış bağlantıları izle
                            self.analyze_network_connection(connection)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(interval)
            except Exception as e:
                logging.error(f"Ağ izleme hatası: {str(e)}")
                time.sleep(interval)
    
    def monitor_autorun(self, interval=300):
        """Otomatik çalışan programları periyodik olarak kontrol eder"""
        # Baseline autorun listesi
        baseline_autoruns = self.check_autorun_entries()
        baseline_autorun_paths = {entry['path'] if 'path' in entry else entry.get('command', '') for entry in baseline_autoruns}
        
        while self.monitoring:
            try:
                # Mevcut autorun listesini al
                current_autoruns = self.check_autorun_entries()
                current_autorun_paths = {entry['path'] if 'path' in entry else entry.get('command', '') for entry in current_autoruns}
                
                # Yeni eklenen otomatik çalışan programları tespit et
                for entry in current_autoruns:
                    path = entry['path'] if 'path' in entry else entry.get('command', '')
                    if path not in baseline_autorun_paths:
                        self._log_alert(
                            "new_autorun",
                            entry.get('name', 'Bilinmeyen'),
                            0,
                            f"Yeni otomatik çalıştırma girişi: {path} (Tür: {entry['type']})",
                            "High"
                        )
                
                # Baseline'ı güncelle
                baseline_autoruns = current_autoruns
                baseline_autorun_paths = current_autorun_paths
                
                time.sleep(interval)
            except Exception as e:
                logging.error(f"Autorun izleme hatası: {str(e)}")
                time.sleep(interval)
    
    def start_monitoring(self):
        """Tüm izleme görevlerini başlatır"""
        if self.monitoring:
            print("İzleme zaten aktif!")
            return
        
        print("Güvenlik izleme sistemi başlatılıyor...")
        logging.info("Güvenlik izleme sistemi başlatıldı")
        
        # Baseline oluştur
        self.establish_baseline()
        
        # İzleme durumunu aktif yap
        self.monitoring = True
        
        # İzleme iş parçacıklarını başlat
        self.process_thread = threading.Thread(target=self.monitor_processes, args=(1,))
        self.network_thread = threading.Thread(target=self.monitor_network, args=(2,))
        self.autorun_thread = threading.Thread(target=self.monitor_autorun, args=(300,))
        
        self.process_thread.daemon = True
        self.network_thread.daemon = True
        self.autorun_thread.daemon = True
        
        self.process_thread.start()
        self.network_thread.start()
        self.autorun_thread.start()
        
        print("Güvenlik izleme aktif. Terminale Ctrl+C ile sonlandırılabilir.")
    
    def stop_monitoring(self):
        """Tüm izleme görevlerini durdurur"""
        self.monitoring = False
        time.sleep(2)  # İş parçacıklarının durdurulması için zaman ver
        print("Güvenlik izleme sistemi durduruldu.")
        logging.info("Güvenlik izleme sistemi durduruldu")
    
    def display_alerts(self):
        """Uyarıları ekranda gösterir"""
        try:
            with open(ALERTS_FILE, 'r') as file:
                reader = csv.reader(file)
                headers = next(reader)  # Başlık satırını atla
                alerts = list(reader)
            
            if not alerts:
                print("Henüz güvenlik uyarısı yok.")
                return
            
            print("\n=== GÜVENLİK UYARILARI ===")
            table = tabulate.tabulate(
                alerts[-10:],  # Son 10 uyarı
                headers=headers,
                tablefmt="grid"
            )
            print(table)
        except Exception as e:
            print(f"Uyarılar gösterilirken hata oluştu: {str(e)}")
    
    def generate_report(self, output_file="security_report.html"):
        """Güvenlik raporu oluşturur"""
        try:
            # Uyarıları yükle
            alerts_df = pd.read_csv(ALERTS_FILE)
            
            # Süreç geçmişini yükle
            process_df = pd.read_csv(PROCESS_HISTORY_FILE)
            
            # Ağ geçmişini yükle
            network_df = pd.read_csv(NETWORK_HISTORY_FILE)
            
            # Rapor HTML'i oluştur
            html = """
            <html>
            <head>
                <title>Windows Güvenlik İzleme Raporu</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1, h2 { color: #333366; }
                    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                    .high { color: #cc0000; font-weight: bold; }
                    .medium { color: #ff6600; }
                    .low { color: #ffcc00; }
                </style>
            </head>
            <body>
                <h1>Windows Güvenlik İzleme Raporu</h1>
                <p>Oluşturulma Tarihi: """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
                
                <h2>Güvenlik Uyarıları</h2>
            """
            
            # Uyarılar tablosu
            if not alerts_df.empty:
                alerts_html = alerts_df.to_html(index=False, classes="table")
                html += alerts_html
            else:
                html += "<p>Güvenlik uyarısı bulunamadı.</p>"
            
            # En aktif süreçler
            html += """
                <h2>En Aktif Süreçler (CPU Kullanımı)</h2>
            """
            
            if not process_df.empty:
                top_processes = process_df.groupby('name')['cpu_percent'].mean().sort_values(ascending=False).head(10)
                plt.figure(figsize=(10, 6))
                top_processes.plot(kind='bar')
                plt.title('En Aktif Süreçler (Ortalama CPU Kullanımı)')
                plt.ylabel('CPU Kullanımı (%)')
                plt.xlabel('Süreç Adı')
                plt.tight_layout()
                plt.savefig('top_processes.png')
                
                html += """<img src="top_processes.png" alt="En Aktif Süreçler" width="800"><br>"""
            else:
                html += "<p>Süreç verisi bulunamadı.</p>"
            
            # Ağ bağlantıları
            html += """
                <h2>Ağ Bağlantıları</h2>
            """
            
            if not network_df.empty:
                top_connections = network_df.groupby('process_name').size().sort_values(ascending=False).head(10)
                plt.figure(figsize=(10, 6))
                top_connections.plot(kind='bar')
                plt.title('En Aktif Ağ Bağlantıları')
                plt.ylabel('Bağlantı Sayısı')
                plt.xlabel('Süreç Adı')
                plt.tight_layout()
                plt.savefig('top_connections.png')
                
                html += """<img src="top_connections.png" alt="En Aktif Ağ Bağlantıları" width="800"><br>"""
                
                # Ağ bağlantı detayları
                html += """<h3>Son Ağ Bağlantıları</h3>"""
                latest_connections = network_df.tail(20)
                html += latest_connections.to_html(index=False, classes="table")
            else:
                html += "<p>Ağ bağlantısı verisi bulunamadı.</p>"
            
            # Son uyarılar
            html += """
                <h2>Son Güvenlik Olayları</h2>
            """
            
            if not alerts_df.empty:
                latest_alerts = alerts_df.tail(20)
                html += latest_alerts.to_html(index=False, classes="table")
            else:
                html += "<p>Güvenlik olayı bulunamadı.</p>"
            
            # HTML sayfasını kapat
            html += """
            </body>
            </html>
            """
            
            # HTML dosyasını kaydet
            with open(output_file, "w") as f:
                f.write(html)
            
            print(f"Güvenlik raporu '{output_file}' dosyasına kaydedildi.")
            return output_file
            
        except Exception as e:
            logging.error(f"Rapor oluşturma hatası: {str(e)}")
            print(f"Rapor oluşturulurken hata oluştu: {str(e)}")
            return None

def main():
    """Ana program fonksiyonu"""
    try:
        print("Windows Güvenlik İzleme Sistemi")
        print("===============================")
        
        # Güvenlik izleyiciyi oluştur
        monitor = SecurityMonitor()
        
        # Menü döngüsü
        while True:
            print("\nMENU:")
            print("1. İzlemeyi Başlat")
            print("2. İzlemeyi Durdur")
            print("3. Uyarıları Göster")
            print("4. Güvenlik Raporu Oluştur")
            print("5. Otomatik Çalışan Programları Kontrol Et")
            print("6. Çıkış")
            
            choice = input("\nSeçiminiz (1-6): ")
            
            if choice == '1':
                monitor.start_monitoring()
            elif choice == '2':
                monitor.stop_monitoring()
            elif choice == '3':
                monitor.display_alerts()
            elif choice == '4':
                report_file = monitor.generate_report()
                if report_file:
                    print(f"Rapor oluşturuldu: {report_file}")
            elif choice == '5':
                autoruns = monitor.check_autorun_entries()
                print("\n=== OTOMATİK ÇALIŞTIRILAN PROGRAMLAR ===")
                for entry in autoruns:
                    if 'path' in entry:
                        print(f"[{entry['type']}] {entry['name']} - {entry['path']}")
                    else:
                        print(f"[{entry['type']}] {entry['name']} - {entry.get('command', 'N/A')}")
            elif choice == '6':
                if monitor.monitoring:
                    monitor.stop_monitoring()
                print("Program sonlandırılıyor...")
                break
            else:
                print("Geçersiz seçim!")
    
    except KeyboardInterrupt:
        print("\nProgram sonlandırılıyor...")
        if monitor.monitoring:
            monitor.stop_monitoring()
    except Exception as e:
        logging.critical(f"Kritik hata: {str(e)}")
        print(f"Beklenmeyen bir hata oluştu: {str(e)}")

if __name__ == "__main__":
    # Gereken kütüphanelerin kontrolü
    missing_libraries = []
    
    try:
        import psutil
    except ImportError:
        missing_libraries.append("psutil")
    
    try:
        import tabulate
    except ImportError:
        missing_libraries.append("tabulate")
    
    try:
        import pandas as pd
    except ImportError:
        missing_libraries.append("pandas")
    
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        missing_libraries.append("matplotlib")
    
    if missing_libraries:
        print("Aşağıdaki kütüphaneler eksik:")
        for lib in missing_libraries:
            print(f"- {lib}")
        print("\nLütfen aşağıdaki komutu çalıştırın:")
        print(f"pip install {' '.join(missing_libraries)}")
        sys.exit(1)
    
    main()