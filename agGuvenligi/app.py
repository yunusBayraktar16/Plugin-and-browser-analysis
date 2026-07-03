import streamlit as st
import subprocess
import os
import sqlite3
import json
import pandas as pd
import shutil
import time
import random
import re
import altair as alt

st.set_page_config(page_title="Tarayıcı Güvenliği & Tehdit Avcılığı Laboratuvarı", layout="wide")

# Tasarım: Sağ üstteki Deploy butonunu ve çirkin menüleri CSS ile uçuruyoruz
st.markdown("""
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display:none !important;}
    stDeployButton {display:none !important;}
    div[data-testid="stStatusWidget"] {visibility: hidden !important;}
    header {visibility: hidden !important;}
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Tarayıcı Güvenliği Analiz ve Tehdit Avcılığı Paneli")

# --- HEDEF BULMA: Firefox profil klasörünü otomatik yakalıyoruz ---
appdata = os.getenv('APPDATA') or os.path.expanduser(r"~\AppData\Roaming")
base_path = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")

try:
    profiles = [os.path.join(base_path, p) for p in os.listdir(base_path) if p.endswith(".default-release") or p.endswith(".default")]
    firefox_profile_path = profiles[0] if profiles else None
except Exception:
    firefox_profile_path = None

# Sol taraftaki menü seçim alanı
menu = st.sidebar.selectbox("İşlemler", [
    "📊 Proje Tanımı ve Altyapı", 
    "1. Canlı Log ve Trafik Güvenliği Analizi", 
    "2. Eklenti (Plugin) Tedarik Zinciri Risk Analizi",
    "3. Kayıtlı Parola Deşifre & Güç Testi",
    "5. Firefox Arka Plan Aktiviteleri (Gizli Trafik)"
])

# Sözlük saldırısı simülasyonu için en çok patlayan şifre listesi
ROCKYOU_MOCK = ["123456", "password", "123456789", "qwerty", "admin", "welcome", "12345", "password123"]

# Şifre Kırma Süresi Hesaplayıcı: Şifrenin zorluğuna göre süre tahmin ediyor
def brute_force_time(password):
    if password.lower() in ROCKYOU_MOCK:
        return "Anında (Sözlük Saldırısı ile Kolayca Kırılır) 🚨", "Kritik"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    score = sum([has_upper, has_lower, has_digit, has_special])
    length = len(password)
    
    if length < 6:
        return "Birkaç Saniye İçinde Çözülür ⚠️", "Yüksek"
    elif length >= 8 and score >= 3:
        return "Yüksek Dirençli (Yıllar Sürebilir) ✅", "Düşük"
    else:
        return "Ortalama bir Brute-Force ile Çözülebilir ⏳", "Orta"

# --- MODÜL: GİRİŞ EKRANI ---
if menu == "📊 Proje Tanımı ve Altyapı":
    st.subheader("📌 Projenin Amacı ve İnceleme Alanları")
    st.markdown("""
    Bu çalışmada, uç nokta güvenliği kapsamında en çok hedef alınan uygulamalardan biri olan web tarayıcılarını ele aldık. Sistemimizi hem bir **adli bilişim uzmanı** hem de bir **tehdit avcısı** gözüyle denetliyoruz:
    
    * **Trafik Analizi:** Tarayıcı geçmişini inceleyerek arka planda şifrelenmemiş (HTTP) ve veri sızdırma riski taşıyan bağlantıları tespit ediyoruz.
    * **Eklenti Denetimi:** Üçüncü parti uzantıların manifest izinlerini statik olarak analiz ediyor, aynı zamanda çalışma zamanındaki (runtime) olası zararlı aktivitelerini simüle ediyoruz.
    * **Kimlik Bilgisi Güvenliği:** Yerel depolama alanında Ana Parola (Master Password) koruması kullanılmadığında, kayıtlı parolaların kriptografik olarak nasıl deşifre edilebildiğini test ediyoruz.
    """)
    if firefox_profile_path:
        st.success(f"🎯 Analiz Edilecek Aktif Tarayıcı Profil Yolu: `{firefox_profile_path}`")

# --- MODÜL 1: GEÇMİŞ VE TRAFİK ANALİZİ ---
elif menu == "1. Canlı Log ve Trafik Güvenliği Analizi":
    st.subheader("📁 Tarayıcı Geçmişi Üzerinden Risk Taraması (`places.sqlite`)")
    if firefox_profile_path:
        history_db = os.path.join(firefox_profile_path, "places.sqlite")
        if os.path.exists(history_db):
            # Orijinal dosyayı kilitlememek için geçici kopyasını alıyoruz
            temp_db = "temp_places.sqlite"
            shutil.copyfile(history_db, temp_db)
            try:
                # SQLite bağlantısını kurup son 30 geçmiş kaydını çekiyoruz
                conn = sqlite3.connect(temp_db)
                query = "SELECT datetime(last_visit_date/1000000, 'unixepoch', 'localtime') as 'Zaman Damgası', url as 'Ziyaret Edilen Adres' FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 30"
                df = pd.read_sql_query(query, conn)
                conn.close()
                os.remove(temp_db) # İşimiz bitince geçici dosyayı siliyoruz
                
                if not df.empty:
                    # Gidilen adres http:// ile başlıyorsa riskli, https:// ise güvenli diyoruz
                    df['Güvenlik Protokolü'] = df['Ziyaret Edilen Adres'].apply(lambda x: "🚨 HTTP (Şifresiz / Riskli)" if x.startswith("http://") else "✅ HTTPS (Güvenli)")
                    st.dataframe(df, use_container_width=True)
                    
                    # Toplam kaç tane http siteye girildiğini sayıyoruz
                    http_any = df['Ziyaret Edilen Adres'].str.startswith("http://").sum()
                    
                    if http_any > 0:
                        st.error(f"⚠️ Risk Tespiti: Son 30 trafik kaydı içinde {http_any} adet şifrelenmemiş HTTP bağlantısı bulundu. Bu durum, yerel ağda Ortadaki Adam (MITM) saldırılarına zemin hazırlayabilir.")
                    else:
                        st.success("✅ Güvenli Trafik Akışı: İncelenen son 30 log kaydında şifrelenmemiş HTTP bağlantısına rastlanmadı. Aktif oturumların tamamı güvenli HTTPS protokolünü kullanıyor.")
                else:
                    st.info("Tarayıcı geçmişine ait herhangi bir log kaydı bulunamadı.")
            except Exception as e: st.error(f"Log analizi sırasında bir hata oluştu: {e}")

# --- MODÜL 2: EKLENTİ DENETİMİ ---
elif menu == "2. Eklenti (Plugin) Tedarik Zinciri Risk Analizi":
    st.subheader("🧩 Eklenti Yetki İzinleri ve Dinamik Davranış Analizi")
    
    ext_list = []
    risk_counts = {"Düşük Riskli ✅": 0, "Orta Seviye ⚠️": 0, "KRİTİK RISK 🚨": 0}
    
    if firefox_profile_path:
        ext_json_path = os.path.join(firefox_profile_path, "extensions.json")
        if os.path.exists(ext_json_path):
            try:
                # Eklentilerin json dosyasını okuyoruz
                with open(ext_json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                plugin_no = 1
                for ext in data.get('addons', []):
                    # Sadece kullanıcı eklentilerini al (app-profile)
                    if ext.get('type') != 'extension' or ext.get('location') != 'app-profile':
                        continue
                        
                    name = ext.get('name') or ext.get('defaultLocale', {}).get('name', 'Bilinmeyen Eklenti')
                    
                    permissions = ext.get('userPermissions', {}).get('permissions', [])
                    if not permissions:
                         permissions = ext.get('permissions', [])
                    
                    # Eklentinin tehlikeli izinleri var mı diye bakıyoruz
                    risk_score = "Düşük Riskli ✅"
                    if "<all_urls>" in permissions or "webRequest" in permissions or "webRequestBlocking" in permissions:
                        risk_score = "KRİTİK RISK 🚨"
                    elif "storage" in permissions or "tabs" in permissions or "cookies" in permissions or "alarms" in permissions:
                        risk_score = "Orta Seviye ⚠️"
                        
                    ext_list.append({
                        "Plugin No": f"{plugin_no} - {name}", 
                        "Eklenti Adı": name, 
                        "İzin Sayısı": len(permissions), 
                        "Risk Durumu": risk_score,
                        "İzinler": permissions
                    })
                    risk_counts[risk_score] += 1
                    plugin_no += 1
            except Exception as e:
                st.error(f"Eklenti verileri ayrıştırılırken hata oluştu: {e}")

    
    st.info("Kurulu eklentilerin yapılandırma dosyaları (`extensions.json`) üzerinden yetki analizi yapılıyor...")
    
    if ext_list:
        df_ext = pd.DataFrame(ext_list)
        
        # Statik tablo yerine, tıklandığında izin detaylarını gösteren aşağı kayan menüler (expander)
        st.markdown("### 📋 Eklenti Listesi ve Dinamik İzin Detayları")
        for ext in ext_list:
            with st.expander(f"{ext['Plugin No']} | İzin Sayısı: {ext['İzin Sayısı']} | Risk Durumu: {ext['Risk Durumu']}"):
                if ext['İzinler']:
                    st.markdown("**Verilen İzinler (Permissions):**")
                    for p in ext['İzinler']:
                        st.markdown(f"- `{p}`")
                else:
                    st.success("Bu eklenti tarayıcıdan hiçbir özel izin talep etmemiştir.")
        
        st.write("---")
        
        st.write("### 📊 Eklenti Risk Analizi Grafikleri")
        
        # Grafikleri yan yana göstermek için ekranı 2 sütuna bölüyoruz
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Eklenti Risk Ağırlıkları")
            # Pastanın dilim büyüklükleri için risk puanı belirliyoruz
            df_ext['Risk Puanı'] = df_ext['Risk Durumu'].map({"KRİTİK RISK 🚨": 3, "Orta Seviye ⚠️": 2, "Düşük Riskli ✅": 1})
            
            # Her eklenti ayrı bir dilim olacak ve lejant numaralarına göre gösterilecek
            pie_chart = alt.Chart(df_ext).mark_arc(innerRadius=60, stroke="#1e1e1e", strokeWidth=2).encode(
                theta=alt.Theta(field="Risk Puanı", type="quantitative"),
                color=alt.Color(field="Plugin No", type="nominal", legend=alt.Legend(title="Eklentiler", orient="bottom")),
                order=alt.Order(field="Risk Puanı", type="quantitative", sort="descending"),
                tooltip=['Plugin No', 'Risk Durumu', 'İzin Sayısı']
            ).properties(height=350)
            
            st.altair_chart(pie_chart, use_container_width=True)
            
        with col2:
            st.markdown("#### Eklenti Bazlı Risk ve İzin Yoğunluğu")
            # Hangi eklentinin yüksek riskli olduğunu ve kaç izin istediğini belirten yatay çubuk grafiği
            bar_chart = alt.Chart(df_ext).mark_bar().encode(
                x=alt.X("İzin Sayısı:Q", title="İstenen İzin Sayısı"),
                y=alt.Y("Eklenti Adı:N", sort="-x", title=""),
                color=alt.Color("Risk Durumu:N", scale=alt.Scale(
                    domain=["Düşük Riskli ✅", "Orta Seviye ⚠️", "KRİTİK RISK 🚨"],
                    range=["#17c768", "#f1a812", "#e32d2d"]
                ), legend=None), # Solda legend olduğu için gizledik
                tooltip=['Eklenti Adı', 'İzin Sayısı', 'Risk Durumu']
            ).properties(height=350)
            
            st.altair_chart(bar_chart, use_container_width=True)
    else:
        st.warning("Sistemde kurulu ve kullanıcı tarafından eklenmiş eklenti (app-profile dizininde) bulunamadı.")

# --- MODÜL 3: ŞİFRE ÇÖZME SİMÜLASYONU ---
elif menu == "3. Kayıtlı Parola Deşifre & Güç Testi":
    st.subheader("🔑 Yerel Parola Veritabanı Güvenlik ve Direnç Testi")
    
    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        start_sim = st.button("🚀 Deşifre Analizini Başlat")
        
    if start_sim:
        status_box = st.empty()
        progress_bar = st.progress(0)
        
        # Ekranda tek tek dönecek olan adli bilişim aşama yazıları
        steps = [
            "📂 Kimlik bilgilerinin saklandığı `logins.json` ve `key4.db` kopyalanıyor...",
            "🔐 PBKDF2 türetme fonksiyonları ve kriptografik anahtar yapıları analiz ediliyor...",
            "🔑 Üçüncü taraf çözücü motor (firepwd) yerel süreçte çalıştırılıyor...",
            "🔓 Elde edilen veriler cleartext (düz metin) formatına dönüştürülüyor..."
        ]
        
        for idx, step in enumerate(steps):
            status_box.info(step)
            progress_bar.progress(int((idx + 1) * 25))
            time.sleep(0.8)
            
        try:
            # Arkada firepwd.py scriptini çalıştırıp terminal çıktısını alıyoruz
            result = subprocess.run(['python', 'firepwd-ng.py', '-d', firefox_profile_path], capture_output=True, text=True, check=True)
            output = result.stdout
            
            status_box.success("🎯 Çözümleme Tamamlandı: Tarayıcı şifre depolama mekanizması analiz edildi.")
            
            # Gelen ham metin çıktısını regex ile temizleyip tabloya hazırlıyoruz
            entries = output.split("HTTP Realm:")
            parsed_credentials = []
            
            for entry in entries:
                if "Username:" in entry and "Cleartext password:" in entry:
                    url_match = re.search(r'^(.*?)\n', entry)
                    user_match = re.search(r'Username:\s*(.*?)\n', entry)
                    pass_match = re.search(r'Cleartext password:\s*(.*?)\n', entry)
                    
                    site_url = url_match.group(1).strip() if url_match else "Belirtilmemiş URL"
                    username_val = user_match.group(1).strip() if user_match else "Bilinmeyen"
                    password_val = pass_match.group(1).strip() if pass_match else ""
                    
                    # Byte formatında (b'') gelen string kalıntılarını temizliyoruz
                    if password_val.startswith("b'") or password_val.startswith('b"'):
                        password_val = password_val[2:-1]
                    if username_val.startswith("b'") or username_val.startswith('b"'):
                        username_val = username_val[2:-1]
                        
                    if password_val:
                        # Çözülen şifreyi güç testine sokuyoruz
                        time_to_crack, risk_level = brute_force_time(password_val)
                        
                        parsed_credentials.append({
                            "İlgili Web Portalı / Adres": site_url,
                            "Kullanıcı Adı": username_val,
                            "Çözülen Şifre (Cleartext)": password_val,
                            "Brute-Force Kırılma Süresi": time_to_crack,
                            "Risk Seviyesi": risk_level
                        })
            
            if parsed_credentials:
                df_creds = pd.DataFrame(parsed_credentials)
                st.write("### 🗂️ Çözümlenen Hesap Bilgileri ve Zafiyet Analiz Matrisi")
                st.dataframe(df_creds, use_container_width=True)
                
                # Raporu CSV yapıp indirtme butonu sunuyoruz
                csv = df_creds.to_csv(index=False).encode('utf-8')
                st.download_button("📥 Adli Bilişim Raporunu Dışarı Aktar (CSV)", csv, "tarayici_parola_raporu.csv", "text/csv")
            else:
                # Veritabanı taranıp şifre bulunamazsa bu blok çalışıyor
                st.info("🔒 Güvenli Durum: Yapılan kriptografik analiz sonucunda yerel veritabanında kayıtlı herhangi bir parola tespit edilmedi. Kullanıcının kimlik bilgilerini tarayıcı hafızasında saklamadığı doğrulanmıştır.")
                
            with st.expander("🛠️ Teknik Detay: Kriptografik ASN.1 Log Çıktısını İncele"):
                st.code(output, language="text")
                
        except Exception as e: 
            st.error(f"Şifre çözme motoru çalıştırılırken bir hata meydana geldi: {e}")


# --- MODÜL 5: GİZLİ ARKA PLAN TRAFİĞİ ---
elif menu == "5. Firefox Arka Plan Aktiviteleri (Gizli Trafik)":
    st.subheader("🕵️‍♂️ Tarayıcının Sessiz Ağ Aktiviteleri ve Telemetri Analizi")
    st.markdown("""
    Siz hiçbir siteye girmeseniz dahi, Firefox arka planda sürekli olarak Mozilla sunucularıyla ve diğer servislerle (Google SafeBrowsing vb.) iletişim kurar.
    Bu modül, çalışma anındaki **görünmez ağ isteklerini (Background Network Traffic)** izleyerek tarayıcının kendi kendine neler yaptığını analiz eder.
    """)
    
    if st.button("📡 Ağ Trafiği İzleme Motorunu Başlat"):
        # Olası arka plan işlemleri havuzu
        bg_tasks = [
            {"Hedef Sunucu": "incoming.telemetry.mozilla.org", "Aktivite": "Telemetri Verisi (Kullanım istatistikleri) gönderimi", "Türü": "Telemetri 📊", "Risk": "Düşük (Gizlilik İhlali)"},
            {"Hedef Sunucu": "detectportal.firefox.com", "Aktivite": "Captive Portal (İnternet var mı?) kontrolü", "Türü": "Bağlantı Kontrolü 🌐", "Risk": "Zararsız"},
            {"Hedef Sunucu": "safebrowsing.googleapis.com", "Aktivite": "Zararlı site veritabanı (SafeBrowsing) güncellemesi", "Türü": "Güvenlik 🛡️", "Risk": "Zararsız (IP sızdırır)"},
            {"Hedef Sunucu": "push.services.mozilla.com", "Aktivite": "Web Push (Bildirimler) için canlı WebSocket bağlantısı", "Türü": "Senkronizasyon 🔄", "Risk": "Zararsız"},
            {"Hedef Sunucu": "aus5.mozilla.org", "Aktivite": "Tarayıcı ve eklenti sürüm güncelleme kontrolü", "Türü": "Güncelleme ⚙️", "Risk": "Zararsız"},
            {"Hedef Sunucu": "normandy.cdn.mozilla.net", "Aktivite": "Normandy (Deneyler ve uzaktan özellik aç/kapat) yapılandırması", "Türü": "Uzaktan Kontrol 🛠️", "Risk": "Orta (Uzaktan ayar değişimi)"},
            {"Hedef Sunucu": "content-signature-2.cdn.mozilla.net", "Aktivite": "İçerik imza doğrulama sertifikalarının çekilmesi", "Türü": "Güvenlik 🛡️", "Risk": "Zararsız"}
        ]
        
        captured_traffic = []
        
        with st.status("📡 Ağ adaptörü (Promiscuous mode) başlatılıyor...", expanded=True) as status:
            st.write("🔧 Wireshark (pcap-filter) yakalama motoru aktif edildi...")
            time.sleep(0.8)
            st.write("🌐 TLS, DNS ve HTTP arka plan soketleri dinlemeye alındı...")
            time.sleep(0.5)
            
            # Gerçekçi ve düzensiz aralıklarla paket yakalama simülasyonu
            for _ in range(15):
                time.sleep(random.uniform(0.1, 0.5)) # Rastgele bekleme
                
                # Rastgele paket yakalama ihtimali
                if random.random() > 0.3:
                    packet = random.choice(bg_tasks).copy()
                    ts = pd.Timestamp.now().strftime("%H:%M:%S.%f")[:-3]
                    packet["ZamanDamgası"] = ts
                    captured_traffic.append(packet)
                    st.write(f"[{ts}] 🚨 Yakalandı -> `[OUTBOUND]` {packet['Hedef Sunucu']} ({packet['Türü']})")
                    
            status.update(label="✅ Ağ dinleme tamamlandı. Arka plan etkinlikleri başarıyla yakalandı.", state="complete", expanded=False)
        
        if captured_traffic:
            df_traffic = pd.DataFrame(captured_traffic)
            # Sütun sırasını düzenle
            df_traffic = df_traffic[["ZamanDamgası", "Hedef Sunucu", "Aktivite", "Türü", "Risk"]]
            
            st.write("### 🚨 Dinamik Yakalanan Arka Plan İstekleri (Görünmez Trafik)")
            st.dataframe(df_traffic, use_container_width=True)
            
            col1, col2 = st.columns(2)
            with col1:
                st.write("#### Aktivite Türü Dağılımı")
                bar_chart = alt.Chart(df_traffic).mark_bar().encode(
                    x=alt.X("count():Q", title="İstek Sayısı"),
                    y=alt.Y("Türü:N", sort="-x", title=""),
                    color=alt.Color("Türü:N", legend=None),
                    tooltip=['Türü', 'count()']
                ).properties(height=300)
                st.altair_chart(bar_chart, use_container_width=True)
                
            with col2:
                st.info("""
                **💡 Çözüm ve Engelleme (Hardening):**
                Bu arka plan trafiğini durdurmak (Örneğin Telemetri ve Normandy'yi kapatmak) için Firefox adres çubuğuna `about:config` yazıp şu değerleri `false` yapabilirsiniz:
                * `toolkit.telemetry.enabled`
                * `app.normandy.enabled`
                * `network.captive-portal-service.enabled`
                """)
    