# Timit Domain & IP Lookup

این یک ابزار ساده برای جستجوی اطلاعات دامنه و IP است که شامل قابلیت‌های زیر می‌شود:
- **Ping**: بررسی وضعیت اتصال به یک هاست.
- **Lookup**: دریافت اطلاعات کامل درباره یک دامنه یا IP (شامل اطلاعات DNS، Reverse DNS و اطلاعات جغرافیایی).

## ویژگی‌ها
- پشتیبانی از جستجوی دامنه و IP.
- نمایش اطلاعات DNS و Reverse DNS.
- نمایش اطلاعات جغرافیایی (کشور، شهر، ISP و غیره).
- قابلیت Ping برای بررسی وضعیت اتصال.
- استفاده از CAPTCHA برای جلوگیری از سوءاستفاده.

## نحوه استفاده

1. دامنه یا IP مورد نظر خود را وارد کنید.
2. حاصل جمع CAPTCHA را وارد کنید.
3. یکی از گزینه‌های زیر را انتخاب کنید:
   - **جستجوی کامل**: دریافت اطلاعات کامل درباره دامنه یا IP.
   - **Ping**: بررسی وضعیت اتصال به هاست.

## نصب

1. کد را دانلود کنید یا از طریق Git Clone دریافت کنید:
   ```bash
   git clone https://github.com/rmombeni/timit-domain-ip-lookup.git


## دریافت API Key

برای استفاده از قابلیت‌های پیشرفته این ابزار (مانند جستجوی اطلاعات IP)، نیاز به یک API Key از سایت [myip.ms](https://myip.ms) دارید. مراحل زیر را برای دریافت API Key دنبال کنید:

1. به سایت [myip.ms](https://myip.ms)بروید.
2. در سایت ثبت‌نام کنید یا اگر حساب کاربری دارید، وارد شوید.
3. پس از ورود، به بخش **API** بروید.
4. یک API Key جدید ایجاد کنید.
5. API Key و API ID دریافتی را در تنظیمات ابزار وارد کنید.

## تنظیمات API

پس از دریافت API Key و API ID، آن‌ها را در بخش لازم وارد کنید:

```php
$api_id = "API_ID_INPUT"; // API ID خود را اینجا وارد کنید
$api_key = "API_KEY_INPUT"; // API Key خود را اینجا وارد کنید
$api_url = "https://api.myip.ms"; // آدرس API


