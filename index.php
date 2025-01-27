<?php
session_start();
// config.php
$api_id = "Api ID";
$api_key = "Api Key";
$api_url = "https://api.myip.ms";

// Generate CAPTCHA
function generateCaptcha() {
    $num1 = rand(1, 20);
    $num2 = rand(1, 20);
    $_SESSION['captcha_result'] = $num1 + $num2;
    return ['num1' => $num1, 'num2' => $num2];
}

function validateCaptcha($userAnswer) {
    return isset($_SESSION['captcha_result']) && 
           intval($userAnswer) === $_SESSION['captcha_result'];
}

function ping($host) {
    // Using a HTTP ping approach instead of system ping
    $starttime = microtime(true);
    $valid = filter_var($host, FILTER_VALIDATE_IP) || 
             filter_var(gethostbyname($host), FILTER_VALIDATE_IP);
    
    if (!$valid) {
        return "آدرس نامعتبر";
    }
    
    $results = [];
    for ($i = 0; $i < 4; $i++) {
        $starttime = microtime(true);
        
        // Try to connect to host
        $fp = @fsockopen($host, 80, $errno, $errstr, 1);
        $endtime = microtime(true);
        
        if ($fp) {
            fclose($fp);
            $time_ms = round(($endtime - $starttime) * 1000, 2);
            $results[] = "زمان پاسخ: {$time_ms} میلی‌ثانیه";
        } else {
            $results[] = "تایم اوت - عدم پاسخ";
        }
        
        // Add small delay between pings
        usleep(250000); // 0.25 seconds
    }
    
    $stats = array_filter($results, function($line) {
        return strpos($line, 'میلی‌ثانیه') !== false;
    });
    
    $output = "نتایج پینگ برای {$host}:\n\n";
    $output .= implode("\n", $results) . "\n\n";
    
    if (count($stats) > 0) {
        $output .= sprintf("تعداد پاسخ‌های موفق: %d از 4\n", count($stats));
    } else {
        $output .= "هیچ پاسخی دریافت نشد";
    }
    
    return $output;
}

function perform_lookup($query) {
    // Basic DNS lookup
    $dns_results = @dns_get_record($query, DNS_ALL) ?: [];
    
    // IP info lookup using ip-api.com
    $ip = filter_var($query, FILTER_VALIDATE_IP) ? $query : gethostbyname($query);
    $ip_info_url = "http://ip-api.com/json/" . urlencode($ip);
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $ip_info_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $ip_info_response = curl_exec($ch);
    curl_close($ch);
    
    $ip_info = json_decode($ip_info_response, true);
    
    // Reverse DNS lookup
    $reverse_dns = gethostbyaddr($ip);
    
    $result = [
        'ip_info' => $ip_info,
        'dns_records' => $dns_results,
        'reverse_dns' => $reverse_dns,
        'query' => $query,
        'resolved_ip' => $ip
    ];
    
    return $result;
}

if (isset($_POST['action'])) {
    if (!validateCaptcha($_POST['captcha'])) {
        echo json_encode(['error' => 'کپچای نادرست']);
        exit;
    }

    $query = trim($_POST['query']);
    if (empty($query)) {
        echo json_encode(['error' => 'لطفا یک دامنه یا IP وارد کنید']);
        exit;
    }

    $action = $_POST['action'];
    
    try {
        $result = '';
        switch($action) {
            case 'ping':
                $result = ping($query);
                echo json_encode(['success' => true, 'result' => $result]);
                break;
                
            case 'traceroute':
                $result = traceroute($query);
                echo json_encode(['success' => true, 'result' => $result]);
                break;
                
            case 'whois':
                $result = whois_query($query);
                echo json_encode(['success' => true, 'result' => $result]);
                break;
                
            case 'lookup':
                $result = perform_lookup($query);
                echo json_encode([
                    'success' => true, 
                    'result' => $result,
                    'type' => 'lookup'
                ]);
                break;
                
            default:
                throw new Exception('عملیات نامعتبر');
        }
    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

// Generate new CAPTCHA for the page load
$captcha = generateCaptcha();
?>


<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>سیستم جستجوی اطلاعات دامنه و IP</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            font-family: 'Vazir', Tahoma, Arial;
            background-color: #f5f5f5;
        }
        .result-box {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-top: 20px;
            padding: 20px;
        }
        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        .tool-button {
            margin: 5px;
        }
        .output-box {
            background: #1e1e1e;
            color: #fff;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            margin-top: 20px;
            max-height: 400px;
            overflow-y: auto;
            direction: ltr;
            text-align: left;
        }
        .error-message {
            color: #dc3545;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-10">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h3 class="mb-0">سیستم جستجوی اطلاعات دامنه و IP</h3>
                    </div>
                    <div class="card-body">
                        <form id="lookupForm">
                            <div class="mb-3">
                                <label for="query" class="form-label">دامنه یا IP مورد نظر را وارد کنید:</label>
                                <input type="text" class="form-control" id="query" name="query" dir="ltr" required>
                            </div>
                            <div class="mb-3">
                                <label for="captcha" class="form-label">لطفاً حاصل جمع را وارد کنید:</label>
                                <div class="input-group">
                                    <span class="input-group-text"><?php echo $captcha['num1'] . ' + ' . $captcha['num2'] . ' = '; ?></span>
                                    <input type="number" class="form-control" id="captcha" name="captcha" required>
                                </div>
                            </div>
                            <div class="btn-group" role="group">
                                <button type="button" class="btn btn-primary tool-button" data-action="lookup">جستجوی کامل</button>
                                <button type="button" class="btn btn-info tool-button" data-action="ping">Ping</button>
                            </div>
                        </form>
                        
                        <div class="loading">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">در حال بارگذاری...</span>
                            </div>
                        </div>
                        
                        <div id="toolOutput" class="output-box" style="display: none;"></div>
                        
                        <div id="results" class="result-box" style="display: none;">
                            <div id="ownerInfo"></div>
                            <div id="reverseDnsInfo"></div>
                            <div id="dnsInfo"></div>
                            <div id="relatedSites"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
   
   
<script>
$(document).ready(function() {
    $('.tool-button').on('click', function(e) {
        e.preventDefault();
        const action = $(this).data('action');
        const query = $('#query').val();
        const captcha = $('#captcha').val();
        
        if (!query || !captcha) {
            alert('لطفاً تمام فیلدها را پر کنید');
            return;
        }
        
        $('.loading').show();
        $('#results, #toolOutput').hide();
        
        $.ajax({
            url: window.location.href,
            method: 'POST',
            data: { 
                action: action,
                query: query,
                captcha: captcha
            },
            success: function(response) {
                $('.loading').hide();
                
                if (typeof response === 'string') {
                    response = JSON.parse(response);
                }
                
                if (response.error) {
                    alert(response.error);
                    return;
                }
                
                if (action === 'lookup') {
                    $('#results').show();
                    displayLookupResults(response.result);
                } else {
                    $('#toolOutput').show().text(response.result);
                }
            },
            error: function() {
                $('.loading').hide();
                alert('خطا در دریافت اطلاعات');
            }
        });
    });

    function displayLookupResults(data) {
        let resultHtml = '<h4>اطلاعات کامل</h4>';
        
        // IP Information
        if (data.ip_info && data.ip_info.status === 'success') {
            resultHtml += `
                <div class="mb-4">
                    <h5>اطلاعات IP</h5>
                    <strong>IP آدرس:</strong> ${data.resolved_ip}<br>
                    <strong>ISP:</strong> ${data.ip_info.isp}<br>
                    <strong>سازمان:</strong> ${data.ip_info.org}<br>
                    <strong>کشور:</strong> ${data.ip_info.country}<br>
                    <strong>شهر:</strong> ${data.ip_info.city}<br>
                    <strong>منطقه زمانی:</strong> ${data.ip_info.timezone}<br>
                </div>`;
        }

        // Reverse DNS
        if (data.reverse_dns) {
            resultHtml += `
                <div class="mb-4">
                    <h5>Reverse DNS</h5>
                    <strong>نام هاست:</strong> ${data.reverse_dns}
                </div>`;
        }

        // DNS Records
        if (data.dns_records && data.dns_records.length > 0) {
            resultHtml += `
                <div class="mb-4">
                    <h5>رکوردهای DNS</h5>
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>نوع</th>
                                    <th>مقدار</th>
                                    <th>TTL</th>
                                </tr>
                            </thead>
                            <tbody>`;

            data.dns_records.forEach(record => {
                resultHtml += `
                    <tr>
                        <td>${record.type}</td>
                        <td>${record.ip ?? record.target ?? record.txt ?? ''}</td>
                        <td>${record.ttl}</td>
                    </tr>`;
            });

            resultHtml += `
                            </tbody>
                        </table>
                    </div>
                </div>`;
        }

        $('#results').html(resultHtml);
    }
});
</script>


   
</body>
</html>
