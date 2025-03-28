// قائمة IPs محظورة
const blockedIPs = new Set();

// قائمة لتخزين عدد الطلبات لكل IP
const requestCounts = new Map();

// دالة لحساب قوة الهجوم (BBS)
function calculateAttackStrength(requestsPerSecond) {
    const bbs = requestsPerSecond * 10; // مثال: قوة الهجوم = عدد الطلبات × 10
    return bbs;
}

// دالة للكشف عن الهجمات
function detectAttack(request) {
    const ip = request.headers.get('cf-connecting-ip') || request.ip; // إذا كنت تستخدم Cloudflare
    const userAgent = request.headers.get('user-agent');
    const contentLength = request.headers.get('content-length');

    // إذا كان IP محظورًا، لا يتم الرد على الطلب
    if (blockedIPs.has(ip)) {
        console.log(`طلب من IP محظور: ${ip}`);
        return { blocked: true };
    }

    // الكشف عن TCP SYN Flood
    if (request.headers.get('cf-socket-bytes-read') === '0' && request.headers.get('cf-socket-bytes-written') === '0') {
        const attackStrength = calculateAttackStrength(100); // مثال: 100 طلب في الثانية
        console.log(`TCP SYN Flood detected from IP: ${ip}`);
        blockedIPs.add(ip);
        return { blocked: true, attackType: "TCP SYN Flood", attackStrength };
    }

    // الكشف عن UDP Flood
    if (request.method === 'UDP') { // UDP Flood (غير شائع في HTTP)
        const attackStrength = calculateAttackStrength(50); // مثال: 50 طلب في الثانية
        console.log(`UDP Flood detected from IP: ${ip}`);
        blockedIPs.add(ip);
        return { blocked: true, attackType: "UDP Flood", attackStrength };
    }

    // الكشف عن ICMP Flood (Ping of Death)
    if (userAgent.includes('Ping')) {
        const attackStrength = calculateAttackStrength(200); // مثال: 200 طلب في الثانية
        console.log(`ICMP Flood detected from IP: ${ip}`);
        blockedIPs.add(ip);
        return { blocked: true, attackType: "ICMP Flood", attackStrength };
    }

    // الكشف عن هجمات HTTP/HTTPS
    if (contentLength > 10000) { // حجم طلب كبير
        const attackStrength = calculateAttackStrength(150); // مثال: 150 طلب في الثانية
        console.log(`HTTP Flood detected from IP: ${ip}`);
        blockedIPs.add(ip);
        return { blocked: true, attackType: "HTTP Flood", attackStrength };
    }

    return { blocked: false };
}

// دالة لإرسال تنبيهات إلى Webhook Discord
async function sendAlert(ip, attackType, attackStrength) {
    const webhookURL = "https://discord.com/api/webhooks/1257946043056918570/iqI1qXHyr90H3-uyMndyThySe7FGdNyooB1Qk_h8rdUrfpk1Xb-CP44MOLCbU9MbpHJ3";
    const data = {
        embeds: [
            {
                title: "🚨 **هجوم محتمل** 🚨",
                fields: [
                    { name: "IP Address", value: ip, inline: true },
                    { name: "نوع الهجوم", value: attackType, inline: true },
                    { name: "قوة الهجوم (BBS)", value: attackStrength.toString(), inline: true }
                ],
                color: 0xFF0000 // لون الرسالة (أحمر)
            }
        ]
    };

    await fetch(webhookURL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    });
}

// دالة لإرسال تأكيد تصفية الهجوم
async function sendFilterConfirmation(ip) {
    const webhookURL = "https://discord.com/api/webhooks/1257946043056918570/iqI1qXHyr90H3-uyMndyThySe7FGdNyooB1Qk_h8rdUrfpk1Xb-CP44MOLCbU9MbpHJ3";
    const data = {
        embeds: [
            {
                title: "✅ **تم تصفية الهجوم** ✅",
                fields: [
                    { name: "IP Address", value: ip, inline: true },
                    { name: "الحالة", value: "تم حظر الهجوم بنجاح", inline: true }
                ],
                color: 0x00FF00 // لون الرسالة (أخضر)
            }
        ]
    };

    await fetch(webhookURL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    });
}

// دالة لتطبيق Rate Limiting
async function applyRateLimit(ip) {
    const now = Date.now();
    const windowSize = 5000; // 5 ثواني
    const maxRequests = 100; // الحد الأقصى للطلبات

    // إزالة الطلبات القديمة
    if (requestCounts.has(ip)) {
        requestCounts.set(ip, requestCounts.get(ip).filter(timestamp => now - timestamp < windowSize));
    } else {
        requestCounts.set(ip, []);
    }

    // إضافة الطلب الحالي
    requestCounts.get(ip).push(now);

    // إذا تجاوز عدد الطلبات الحد المسموح
    if (requestCounts.get(ip).length > maxRequests) {
        blockedIPs.add(ip);
        await sendAlert(ip, "Rate Limit Exceeded", requestCounts.get(ip).length);
        await sendFilterConfirmation(ip);
        return false; // تم حظر IP
    }

    return true; // الطلب مسموح
}

// دالة للتعامل مع الطلبات
async function handleRequest(request) {
    const ip = request.headers.get('cf-connecting-ip') || request.ip;

    // إذا كان IP محظورًا، لا يتم الرد على الطلب
    if (blockedIPs.has(ip)) {
        console.log(`طلب من IP محظور: ${ip}`);
        return new Response(null, { status: 403 }); // لا يتم إرسال أي رد
    }

    // تطبيق Rate Limiting
    const isAllowed = await applyRateLimit(ip);
    if (!isAllowed) {
        return new Response(null, { status: 429 }); // Too Many Requests
    }

    // تأخير 0.1 ثانية قبل إرسال الطلب
    await new Promise(resolve => setTimeout(resolve, 100));

    const attackResult = detectAttack(request);

    if (attackResult.blocked) {
        await sendAlert(ip, attackResult.attackType, attackResult.attackStrength);
        await sendFilterConfirmation(ip);
        return new Response(null, { status: 403 }); // لا يتم إرسال أي رد
    }

    // إذا لم يتم اكتشاف هجوم، قم بتحويل الطلب إلى الموقع
    return fetch(request);
}

// بدء الحماية
addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});