Bu Windows Güvenlik İzleme Sistemi, 
Bilgisayarınızdaki şüpheli işlemleri ve ağ etkinliklerini tespit etmek için 
kapsamlı bir araçtır. Programın ana özellikleri şunlardır:

# Özellikleri:

## Şüpheli Süreç Tespiti

Bilinen kötü amaçlı yazılım isimlerini izleme
Şüpheli komut satırı parametrelerini kontrol etme
Anormal CPU ve bellek kullanımını tespit etme
SYSTEM kullanıcısı altında çalışan şüpheli süreçleri tespit etme


## Ağ Aktivite İzleme

Şüpheli portlara yapılan bağlantıları tespit etme
Şüpheli süreçler tarafından yapılan ağ bağlantılarını izleme
Anormal sayıda ağ bağlantısı olan süreçleri tespit etme


## Otomatik Başlayan Programları İzleme

Windows başlangıç klasörlerini tarama
Registry'deki otomatik başlatma girişlerini kontrol etme
Yeni eklenen otomatik başlatma girişlerini tespit etme


## Akıllı Analiz ve Raporlama

Normal sistem davranışını öğrenerek (baseline) anomalileri tespit etme
Düzenli güvenlik raporları oluşturma
CSV dosyalarına kayıt tutma
Grafikli raporlar oluşturma



## Kurulum ve Kullanım:

**Gereken Kütüphaneler:**
pip install psutil tabulate pandas matplotlib

**Programı Çalıştırma:**
python security_monitor.py

**Program Menüsü:**

**İzlemeyi Başlat:** Sistem izlemeyi başlatır
**İzlemeyi Durdur:** İzlemeyi sonlandırır
**Uyarıları Göster:** Tespit edilen güvenlik uyarılarını listeler
**Güvenlik Raporu Oluştur:** HTML formatında detaylı bir rapor oluşturur
**Otomatik Çalışan Programları Kontrol Et:** Sistem başlangıcında çalışan programları listeler
**Çıkış:** Programı sonlandırır



## Nasıl Çalışır:

Program başlatıldığında, önce sistemin normal davranış profilini oluşturur (baseline)
Ardından paralel iş parçacıkları ile:

Süreçleri izler
Ağ bağlantılarını kontrol eder
Otomatik başlayan programlardaki değişimleri takip eder


**Şüpheli durumlar tespit edildiğinde:**

Log dosyasına kaydeder
CSV'ye uyarı ekler
Kullanıcıya bildirim verir


Kullanıcı istediğinde detaylı raporlar oluşturabilir

**Bu araç, Windows sistemlerindeki güvenlik durumunuzu izlemek ve potansiyel tehditleri erken tespit etmek için faydalı olacaktır. İsterseniz programı daha da geliştirebilir, örneğin şüpheli dosya değişimlerini izleme, e-posta bildirimleri gönderme veya daha gelişmiş anomali tespiti ekleme gibi özellikler ekleyebilirsiniz.**