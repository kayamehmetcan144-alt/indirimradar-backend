# 🚂 Railway Deployment Rehberi

## ADIM 1: Railway Hesabı Oluştur

1. **https://railway.app** adresine git
2. **"Start a New Project"** butonuna tıkla
3. **GitHub ile giriş yap** (önerilir)
   - GitHub hesabın yoksa ücretsiz oluştur: https://github.com/signup

## ADIM 2: Backend Kodunu GitHub'a Yükle

### GitHub Repository Oluştur:

1. **https://github.com/new** adresine git
2. Repository adı: `indirimradar-backend`
3. ✅ Public (ücretsiz) veya Private (ücretli)
4. ❌ Initialize with README (kapalı bırak)
5. **"Create repository"** butonuna tıkla

### Kodları GitHub'a Yükle:

```bash
# Terminal'de backend klasörüne git
cd /path/to/backend

# Git başlat
git init

# Tüm dosyaları ekle
git add .

# Commit yap
git commit -m "Initial commit: İndirimRadar Backend API"

# GitHub'a bağla (yukarıdaki URL'i kullan)
git remote add origin https://github.com/KULLANICI_ADIN/indirimradar-backend.git

# Push et
git branch -M main
git push -u origin main
```

**Not:** Eğer Git'i bilmiyorsan, dosyaları manuel upload edebilirsin:
- GitHub repository sayfasında **"uploading an existing file"** linkine tıkla
- Tüm backend dosyalarını sürükle-bırak

## ADIM 3: Railway'de Proje Oluştur

1. Railway Dashboard → **"New Project"**
2. **"Deploy from GitHub repo"** seç
3. **indirimradar-backend** repository'sini seç
4. Railway otomatik olarak detect edecek ve deploy başlayacak

## ADIM 4: PostgreSQL Database Ekle

1. Railway projesinde → **"New"** butonuna tıkla
2. **"Database"** → **"Add PostgreSQL"** seç
3. Railway otomatik database oluşturacak
4. Database otomatik olarak backend'e bağlanacak

## ADIM 5: Environment Variables Ayarla

Railway Dashboard → Backend Service → **"Variables"** sekmesi

Şu değişkenleri ekle:

```
SECRET_KEY=SuperSecure-RandomKey-Change-This-123456789
JWT_SECRET_KEY=Another-Secret-Key-For-JWT-987654321
FLASK_ENV=production
ALLOWED_ORIGINS=https://indirimradar.com,https://www.indirimradar.com,https://indirimradar.vercel.app
SCRAPING_ENABLED=true
SCRAPING_INTERVAL_HOURS=6
LOG_LEVEL=INFO
```

**Not:** `DATABASE_URL` otomatik eklenir, sen ekleme!

## ADIM 6: Deploy'u İzle

1. **"Deployments"** sekmesine git
2. Log'ları izle
3. ✅ "Build successful" mesajını bekle
4. ✅ "Deploy successful" mesajını bekle

## ADIM 7: Public URL Al

1. Railway Dashboard → **"Settings"** sekmesi
2. **"Generate Domain"** butonuna tıkla
3. URL örneği: `indirimradar-backend-production.up.railway.app`
4. Bu URL'i kopyala → API Base URL olarak kullanacaksın

## ADIM 8: Test Et

### Health Check:
```bash
curl https://YOUR-RAILWAY-URL.railway.app/health
```

Beklenen cevap:
```json
{
  "status": "healthy",
  "database": "connected",
  "timestamp": "2026-01-30T..."
}
```

### Ana Endpoint:
```bash
curl https://YOUR-RAILWAY-URL.railway.app/
```

### Products API:
```bash
curl https://YOUR-RAILWAY-URL.railway.app/api/products
```

## ADIM 9: Database'i Başlat

İlk deploy'dan sonra database boş olacak. Sample data eklemek için:

**Seçenek A - Otomatik:** İlk çalıştırmada app.py sample data ekler

**Seçenek B - Manuel:**
```bash
# Railway CLI kur (opsiyonel)
npm install -g @railway/cli

# Login
railway login

# Projeye bağlan
railway link

# Database'e bağlan
railway run python

# Python console'da:
>>> from app import app, db, Product, PriceHistory
>>> with app.app_context():
>>>     db.create_all()
>>>     print("Database initialized!")
```

## ADIM 10: Custom Domain Ekle (Opsiyonel)

Şimdilik Railway subdomain'i kullan. 
Domain aldıktan sonra Cloudflare üzerinden bağlayacağız.

---

## ⚠️ ÖNEMLİ NOTLAR:

### Railway Ücretsiz Plan:
- ✅ $5 ücretsiz kredi (ayda)
- ✅ 500 saat execution time
- ✅ PostgreSQL dahil
- ⚠️ Kredi bitince uygulamayı durdurur (uyarı gelir)

### Ortalama Maliyet:
- Düşük trafik: **$0-5/ay** (ücretsiz)
- Orta trafik: **$5-15/ay**

### Log'ları İzleme:
```bash
railway logs
```

### Yeniden Deploy:
GitHub'a yeni commit atınca otomatik deploy olur:
```bash
git add .
git commit -m "Update: yeni özellik"
git push
```

---

## ✅ BAŞARI KRİTERLERİ:

- ✅ Railway'de proje oluşturuldu
- ✅ GitHub'dan otomatik deploy çalışıyor
- ✅ PostgreSQL database bağlandı
- ✅ Environment variables ayarlandı
- ✅ Public URL çalışıyor
- ✅ /health endpoint OK dönüyor
- ✅ /api/products endpoint çalışıyor

---

## 🆘 SORUN ÇÖZME:

### Deploy başarısız olursa:
1. Railway logs'u kontrol et
2. requirements.txt doğru mu?
3. Python versiyonu uyumlu mu?

### Database bağlanamıyorsa:
1. DATABASE_URL otomatik eklendi mi?
2. PostgreSQL service çalışıyor mu?

### Environment variables kayboluyorsa:
1. Railway dashboard'dan tekrar ekle
2. Redeploy yap

---

**Backend deploy tamamlandıktan sonra Cloudflare kurulumuna geçeceğiz! 🚀**
