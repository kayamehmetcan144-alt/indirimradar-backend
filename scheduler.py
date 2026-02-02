from apscheduler.schedulers.background import BackgroundScheduler
from scraper import scheduled_scraping
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def start_scheduler():
    """
    Scheduler başlat - Her 6 saatte bir scraping yap
    """
    scheduler = BackgroundScheduler()
    
    # Her 6 saatte bir çalış
    scheduler.add_job(
        scheduled_scraping,
        'interval',
        hours=6,
        id='scraping_job',
        name='Product Scraping Job',
        replace_existing=True
    )
    
    # İlk scraping'i hemen yap
    scheduler.add_job(
        scheduled_scraping,
        'date',
        id='initial_scraping',
        name='Initial Scraping',
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("✅ Scheduler started! Scraping will run every 6 hours.")
    
    return scheduler

if __name__ == '__main__':
    scheduler = start_scheduler()
    
    # Keep the script running
    try:
        while True:
            pass
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
