const { chromium } = require('@playwright/test');

(async () => {
  console.log('[PW-CHECK] Starting Playwright verification...');
  
  try {
    console.log('[PW-CHECK] Launching Chromium...');
    const browser = await chromium.launch({ headless: true });
    console.log('[PW-CHECK] Browser launched successfully');
    
    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    console.log('[PW-CHECK] Page created');
    
    console.log('[PW-CHECK] Navigating to example.com...');
    await page.goto('https://example.com', { waitUntil: 'networkidle' });
    console.log('[PW-CHECK] Page loaded');
    
    const title = await page.title();
    console.log(`[PW-CHECK] Page title: ${title}`);
    
    await browser.close();
    console.log('[PW-CHECK] SUCCESS: Playwright is working correctly');
    process.exit(0);
    
  } catch (error) {
    console.error('[PW-CHECK] ERROR:', error.message);
    console.error('[PW-CHECK] FAILED: Playwright is not working');
    process.exit(1);
  }
})();
