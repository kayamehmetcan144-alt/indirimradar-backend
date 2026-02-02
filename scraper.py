import requests
from bs4 import BeautifulSoup
import re
import json
import time
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options

class ProductScraper:
    """
    Web scraping sınıfı - Türkiye'nin büyük e-ticaret platformlarından ürün ve fiyat bilgisi çeker
    """
    
    def __init__(self, headless=True):
        self.headless = headless
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
    
    def setup_selenium(self):
        """Selenium WebDriver kurulumu"""
        chrome_options = Options()
        if self.headless:
            chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        driver = webdriver.Chrome(options=chrome_options)
        return driver
    
    # ==================== TRENDYOL SCRAPER ====================
    
    def scrape_trendyol_category(self, category_url, max_products=50):
        """
        Trendyol'dan kategori sayfasından ürünleri çeker
        Örnek URL: https://www.trendyol.com/elektronik-x-c103498
        """
        products = []
        driver = self.setup_selenium()
        
        try:
            driver.get(category_url)
            time.sleep(3)
            
            # Sayfayı scroll et (lazy loading için)
            for i in range(5):
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(1)
            
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            
            # Ürün kartlarını bul
            product_cards = soup.find_all('div', class_=re.compile('p-card-wrppr'))[:max_products]
            
            for card in product_cards:
                try:
                    # Başlık
                    title_elem = card.find('span', class_='prdct-desc-cntnr-name')
                    if not title_elem:
                        continue
                    title = title_elem.text.strip()
                    
                    # Fiyatlar
                    current_price_elem = card.find('div', class_='prc-box-dscntd')
                    if not current_price_elem:
                        current_price_elem = card.find('div', class_='prc-box-sllng')
                    
                    if not current_price_elem:
                        continue
                    
                    current_price_text = current_price_elem.text.strip()
                    current_price = self.parse_price(current_price_text)
                    
                    # Eski fiyat
                    old_price_elem = card.find('div', class_='prc-box-orgnl')
                    if old_price_elem:
                        old_price = self.parse_price(old_price_elem.text.strip())
                    else:
                        old_price = current_price
                    
                    # İndirim oranı
                    discount_elem = card.find('div', class_='product-percentage-tag')
                    if discount_elem:
                        discount_text = discount_elem.text.strip()
                        discount = int(re.search(r'\d+', discount_text).group())
                    else:
                        discount = 0
                    
                    # Görsel
                    img_elem = card.find('img', class_='p-card-img')
                    image_url = img_elem['src'] if img_elem and 'src' in img_elem.attrs else ''
                    
                    # Ürün linki
                    link_elem = card.find('a', href=True)
                    product_url = 'https://www.trendyol.com' + link_elem['href'] if link_elem else ''
                    
                    # Kategori tahmin et
                    category = self.detect_category(title)
                    
                    product = {
                        'title': title,
                        'platform': 'Trendyol',
                        'category': category,
                        'current_price': current_price,
                        'original_price': old_price,
                        'discount_percent': discount,
                        'image_url': image_url,
                        'product_url': product_url,
                        'real_deal_status': self.calculate_real_deal(current_price, old_price, discount)
                    }
                    
                    products.append(product)
                    
                except Exception as e:
                    print(f"Error parsing Trendyol product: {e}")
                    continue
            
        finally:
            driver.quit()
        
        return products
    
    # ==================== HEPSİBURADA SCRAPER ====================
    
    def scrape_hepsiburada_category(self, category_url, max_products=50):
        """
        Hepsiburada'dan kategori sayfasından ürünleri çeker
        Örnek URL: https://www.hepsiburada.com/elektronik-c-2147483642
        """
        products = []
        driver = self.setup_selenium()
        
        try:
            driver.get(category_url)
            time.sleep(3)
            
            # Scroll
            for i in range(5):
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(1)
            
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            
            # Ürün listesi
            product_cards = soup.find_all('li', class_='productListContent-item')[:max_products]
            
            for card in product_cards:
                try:
                    # Başlık
                    title_elem = card.find('h3', {'data-test-id': 'product-card-name'})
                    if not title_elem:
                        continue
                    title = title_elem.text.strip()
                    
                    # Fiyat
                    price_elem = card.find('div', {'data-test-id': 'price-current-price'})
                    if not price_elem:
                        continue
                    current_price = self.parse_price(price_elem.text.strip())
                    
                    # Eski fiyat
                    old_price_elem = card.find('div', {'data-test-id': 'price-old-price'})
                    if old_price_elem:
                        old_price = self.parse_price(old_price_elem.text.strip())
                    else:
                        old_price = current_price
                    
                    # İndirim
                    discount = 0
                    if old_price > current_price:
                        discount = round(((old_price - current_price) / old_price) * 100)
                    
                    # Görsel
                    img_elem = card.find('img', {'data-test-id': 'product-card-image'})
                    image_url = img_elem['src'] if img_elem and 'src' in img_elem.attrs else ''
                    
                    # Link
                    link_elem = card.find('a', href=True)
                    product_url = 'https://www.hepsiburada.com' + link_elem['href'] if link_elem else ''
                    
                    category = self.detect_category(title)
                    
                    product = {
                        'title': title,
                        'platform': 'Hepsiburada',
                        'category': category,
                        'current_price': current_price,
                        'original_price': old_price,
                        'discount_percent': discount,
                        'image_url': image_url,
                        'product_url': product_url,
                        'real_deal_status': self.calculate_real_deal(current_price, old_price, discount)
                    }
                    
                    products.append(product)
                    
                except Exception as e:
                    print(f"Error parsing Hepsiburada product: {e}")
                    continue
            
        finally:
            driver.quit()
        
        return products
    
    # ==================== N11 SCRAPER ====================
    
    def scrape_n11_category(self, category_url, max_products=50):
        """
        N11'den kategori sayfasından ürünleri çeker
        Örnek URL: https://www.n11.com/elektronik
        """
        products = []
        
        try:
            response = self.session.get(category_url)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            product_cards = soup.find_all('li', class_='column')[:max_products]
            
            for card in product_cards:
                try:
                    # Başlık
                    title_elem = card.find('h3', class_='productName')
                    if not title_elem:
                        continue
                    title = title_elem.text.strip()
                    
                    # Fiyat
                    price_elem = card.find('ins')
                    if not price_elem:
                        price_elem = card.find('div', class_='priceContainer')
                    
                    if not price_elem:
                        continue
                    
                    current_price = self.parse_price(price_elem.text.strip())
                    
                    # Eski fiyat
                    old_price_elem = card.find('del')
                    if old_price_elem:
                        old_price = self.parse_price(old_price_elem.text.strip())
                    else:
                        old_price = current_price
                    
                    # İndirim
                    discount_elem = card.find('div', class_='discountPercentage')
                    if discount_elem:
                        discount = int(re.search(r'\d+', discount_elem.text).group())
                    else:
                        discount = 0
                    
                    # Görsel
                    img_elem = card.find('img', class_='lazy')
                    image_url = img_elem.get('data-original', '') or img_elem.get('src', '')
                    
                    # Link
                    link_elem = card.find('a', class_='plink')
                    product_url = 'https:' + link_elem['href'] if link_elem and 'href' in link_elem.attrs else ''
                    
                    category = self.detect_category(title)
                    
                    product = {
                        'title': title,
                        'platform': 'N11',
                        'category': category,
                        'current_price': current_price,
                        'original_price': old_price,
                        'discount_percent': discount,
                        'image_url': image_url,
                        'product_url': product_url,
                        'real_deal_status': self.calculate_real_deal(current_price, old_price, discount)
                    }
                    
                    products.append(product)
                    
                except Exception as e:
                    print(f"Error parsing N11 product: {e}")
                    continue
            
        except Exception as e:
            print(f"Error scraping N11: {e}")
        
        return products
    
    # ==================== HELPER METHODS ====================
    
    def parse_price(self, price_text):
        """Fiyat metnini sayıya çevirir"""
        # Sadece rakamları ve noktayı/virgülü al
        price_text = re.sub(r'[^\d,.]', '', price_text)
        price_text = price_text.replace('.', '').replace(',', '.')
        
        try:
            return float(price_text)
        except:
            return 0.0
    
    def detect_category(self, title):
        """Ürün başlığından kategori tahmin eder"""
        title_lower = title.lower()
        
        if any(word in title_lower for word in ['iphone', 'samsung', 'laptop', 'tablet', 'kulaklık', 'televizyon', 'tv', 'telefon', 'bilgisayar']):
            return 'Elektronik'
        elif any(word in title_lower for word in ['ayakkabı', 'gömlek', 'pantolon', 'elbise', 'ceket', 'kazak', 'tshirt']):
            return 'Moda'
        elif any(word in title_lower for word in ['masa', 'sandalye', 'koltuk', 'yatak', 'dolap', 'lamba']):
            return 'Ev & Yaşam'
        elif any(word in title_lower for word in ['playstation', 'xbox', 'nintendo', 'oyun', 'konsol']):
            return 'Oyun'
        elif any(word in title_lower for word in ['parfüm', 'makyaj', 'cilt', 'saç', 'serum', 'krem']):
            return 'Kozmetik'
        else:
            return 'Diğer'
    
    def calculate_real_deal(self, current_price, old_price, discount):
        """Gerçek indirim durumunu hesaplar"""
        if discount >= 30:
            return 'real'
        elif discount >= 15:
            return 'normal'
        else:
            return 'fake'
    
    # ==================== MAIN SCRAPER ====================
    
    def scrape_all_platforms(self, categories_per_platform=2, products_per_category=20):
        """Tüm platformlardan ürün çeker"""
        all_products = []
        
        # Trendyol
        print("Scraping Trendyol...")
        trendyol_categories = [
            'https://www.trendyol.com/sr?q=indirim',
            'https://www.trendyol.com/sr?q=kampanya'
        ]
        
        for url in trendyol_categories[:categories_per_platform]:
            try:
                products = self.scrape_trendyol_category(url, products_per_category)
                all_products.extend(products)
                print(f"✅ Trendyol: {len(products)} ürün eklendi")
                time.sleep(2)
            except Exception as e:
                print(f"❌ Trendyol hatası: {e}")
        
        # Hepsiburada
        print("\nScraping Hepsiburada...")
        hepsiburada_categories = [
            'https://www.hepsiburada.com/firsatlar',
        ]
        
        for url in hepsiburada_categories[:categories_per_platform]:
            try:
                products = self.scrape_hepsiburada_category(url, products_per_category)
                all_products.extend(products)
                print(f"✅ Hepsiburada: {len(products)} ürün eklendi")
                time.sleep(2)
            except Exception as e:
                print(f"❌ Hepsiburada hatası: {e}")
        
        # N11
        print("\nScraping N11...")
        n11_categories = [
            'https://www.n11.com/kampanyalar',
        ]
        
        for url in n11_categories[:categories_per_platform]:
            try:
                products = self.scrape_n11_category(url, products_per_category)
                all_products.extend(products)
                print(f"✅ N11: {len(products)} ürün eklendi")
                time.sleep(2)
            except Exception as e:
                print(f"❌ N11 hatası: {e}")
        
        print(f"\n🎉 Toplam {len(all_products)} ürün toplandı!")
        return all_products
    
    def save_to_json(self, products, filename='scraped_products.json'):
        """Ürünleri JSON dosyasına kaydeder"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(products, f, ensure_ascii=False, indent=2)
        print(f"💾 Ürünler {filename} dosyasına kaydedildi")

# ==================== SCHEDULER ====================

def scheduled_scraping():
    """Otomatik scraping görevi - Her 6 saatte bir çalışır"""
    from app import app, db, Product, PriceHistory
    
    scraper = ProductScraper(headless=True)
    products = scraper.scrape_all_platforms(categories_per_platform=2, products_per_category=30)
    
    with app.app_context():
        for product_data in products:
            # Check if product exists
            existing = Product.query.filter_by(
                title=product_data['title'],
                platform=product_data['platform']
            ).first()
            
            if existing:
                # Update price
                old_price = existing.current_price
                existing.current_price = product_data['current_price']
                existing.original_price = product_data['original_price']
                existing.discount_percent = product_data['discount_percent']
                existing.real_deal_status = product_data['real_deal_status']
                existing.updated_at = datetime.utcnow()
                
                # Add to price history if changed
                if old_price != product_data['current_price']:
                    history = PriceHistory(
                        product_id=existing.id,
                        price=product_data['current_price']
                    )
                    db.session.add(history)
            else:
                # Create new product
                new_product = Product(**product_data)
                db.session.add(new_product)
                db.session.commit()
                
                # Add initial price history
                history = PriceHistory(
                    product_id=new_product.id,
                    price=product_data['current_price']
                )
                db.session.add(history)
        
        db.session.commit()
        print(f"✅ Database updated with {len(products)} products")

# ==================== STANDALONE USAGE ====================

if __name__ == '__main__':
    scraper = ProductScraper(headless=False)
    
    # Test single platform
    print("Testing Trendyol scraper...")
    products = scraper.scrape_trendyol_category('https://www.trendyol.com/sr?q=indirim', max_products=10)
    
    print(f"\n✅ Found {len(products)} products")
    for p in products[:3]:
        print(f"\n📦 {p['title']}")
        print(f"   💰 {p['current_price']} TL (eski: {p['original_price']} TL)")
        print(f"   🔥 %{p['discount_percent']} indirim")
        print(f"   {p['real_deal_status']}")
    
    # Save to JSON
    scraper.save_to_json(products)
