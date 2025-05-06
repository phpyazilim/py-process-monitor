import psutil
import time
from datetime import datetime
import os
import sys
import tabulate
# pip3 install psutil tabulate

def get_size(bytes):
    """
    Bayt değerini okunabilir bir formata dönüştürür (KB, MB, GB)
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024

def get_process_info():
    """
    Tüm işlemler hakkında bilgi toplar ve bir liste olarak döndürür
    """
    processes_info = []
    
    for process in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_info', 'create_time']):
        try:
            # Süreç bilgilerini al
            process_info = process.info
            
            # Bellek kullanımını hesapla
            memory_usage = get_size(process_info['memory_info'].rss)
            
            # Süreç başlangıç zamanını hesapla
            start_time = datetime.fromtimestamp(process_info['create_time']).strftime('%Y-%m-%d %H:%M:%S')
            
            # CPU kullanımını al ve yüzde biçiminde göster
            cpu_usage = f"{process_info['cpu_percent']:.2f}%"
            
            # İşlemle ilgili bilgileri bir sözlükte topla
            info = {
                'PID': process_info['pid'],
                'İsim': process_info['name'],
                'Durum': process_info['status'],
                'Kullanıcı': process_info['username'],
                'CPU': cpu_usage,
                'Bellek': memory_usage,
                'Başlangıç Zamanı': start_time
            }
            
            # Komut satırı argümanlarını almaya çalış
            try:
                if process.pid != os.getpid():  # Kendi sürecimizi kontrol etmeye çalışmaktan kaçın
                    cmdline = " ".join(process.cmdline())
                    info['Komut'] = cmdline if cmdline else "N/A"
                else:
                    info['Komut'] = "Bu program"
            except (psutil.AccessDenied, psutil.ZombieProcess):
                info['Komut'] = "Erişim Engellendi"
            
            # Süreç bilgisini listeye ekle
            processes_info.append(info)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return processes_info

def save_to_file(processes_info, filename="process_info.txt"):
    """
    Süreç bilgilerini bir dosyaya kaydeder
    """
    with open(filename, "w", encoding="utf-8") as f:
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"Süreç Raporu - {current_time}\n\n")
        
        headers = ['PID', 'İsim', 'Durum', 'Kullanıcı', 'CPU', 'Bellek', 'Başlangıç Zamanı', 'Komut']
        table = [[process[header] for header in headers] for process in processes_info]
        
        f.write(tabulate.tabulate(table, headers=headers, tablefmt="grid"))
        f.write("\n\nToplam Süreç Sayısı: " + str(len(processes_info)))
    
    print(f"Bilgiler '{filename}' dosyasına kaydedildi.")

def monitor_processes(interval=5, duration=None, save=False):
    """
    Belirli bir süre boyunca süreçleri izler ve bilgilerini görüntüler
    
    :param interval: Yenileme aralığı (saniye)
    :param duration: İzleme süresi (saniye), None değeri sürekli izleme yapar
    :param save: True ise sonuçları dosyaya kaydet
    """
    try:
        elapsed_time = 0
        while True:
            # Ekranı temizle
            os.system('cls' if os.name == 'nt' else 'clear')
            
            # Süreç bilgilerini al
            processes_info = get_process_info()
            
            # CPU ve bellek kullanımına göre sırala
            sorted_processes = sorted(processes_info, key=lambda x: float(x['CPU'].strip('%')), reverse=True)
            
            # Üst bilgiyi yazdır
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"Windows Süreç İzleyici - {current_time}")
            print(f"Toplam Süreç Sayısı: {len(sorted_processes)}")
            print("\nEn Çok CPU Kullanan İşlemler:")
            
            # İlk 10 süreci görüntüle
            headers = ['PID', 'İsim', 'Durum', 'Kullanıcı', 'CPU', 'Bellek', 'Başlangıç Zamanı']
            table = [[process[header] for header in headers] for process in sorted_processes[:10]]
            
            print(tabulate.tabulate(table, headers=headers, tablefmt="grid"))
            
            # Dosyaya kaydet seçeneği
            if save:
                save_to_file(sorted_processes)
            
            # Belirtilen süre doldu mu kontrol et
            if duration is not None:
                elapsed_time += interval
                if elapsed_time >= duration:
                    print("\nİzleme tamamlandı.")
                    break
            
            # Bir sonraki güncelleme için bekle
            print(f"\nYenilemek için {interval} saniye bekleniyor... (Çıkış için Ctrl+C)")
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\nProgram sonlandırıldı.")
        if save:
            save_to_file(get_process_info())

def main():
    """
    Ana program
    """
    print("Windows Süreç İzleyici")
    print("----------------------")
    
    try:
        # Özel ayarlar
        save_option = input("Sonuçları dosyaya kaydetmek ister misiniz? (e/h): ").lower() == 'e'
        
        interval = 5  # Varsayılan
        try:
            interval_input = input(f"Yenileme aralığı (saniye) [{interval}]: ")
            if interval_input:
                interval = int(interval_input)
        except ValueError:
            print(f"Geçersiz değer, varsayılan aralık ({interval} saniye) kullanılıyor.")
        
        duration = None  # Varsayılan (sürekli izleme)
        try:
            duration_input = input("İzleme süresi (saniye), sürekli izleme için boş bırakın: ")
            if duration_input:
                duration = int(duration_input)
        except ValueError:
            print("Geçersiz değer, sürekli izleme modu etkinleştiriliyor.")
        
        # Süreç izlemeyi başlat
        monitor_processes(interval, duration, save_option)
        
    except Exception as e:
        print(f"Hata oluştu: {e}")

if __name__ == "__main__":
    # psutil ve tabulate kütüphanelerinin yüklü olup olmadığını kontrol et
    try:
        import psutil
        try:
            import tabulate
        except ImportError:
            print("'tabulate' kütüphanesi bulunamadı. Lütfen aşağıdaki komutu çalıştırın:")
            print("pip install tabulate")
            sys.exit(1)
    except ImportError:
        print("'psutil' kütüphanesi bulunamadı. Lütfen aşağıdaki komutu çalıştırın:")
        print("pip install psutil")
        sys.exit(1)
    
    main()