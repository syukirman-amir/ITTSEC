
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hero vs Boss - Web4 (AES + HMAC)</title>
    <script src="js/crypto-utils.js"></script>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .container { max-width: 500px; margin: 40px auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .boss, .hero { margin-bottom: 20px; }
        .hpbar-bg { width: 100%; height: 18px; background: #eee; border-radius: 8px; margin: 6px 0; }
        .hpbar { height: 18px; background: linear-gradient(90deg, #b30000, #ff6666); border-radius: 8px; transition: width 0.7s cubic-bezier(.68,-0.55,.27,1.55); }
        .hpbar-hero { background: linear-gradient(90deg, #0077b3, #66ccff); }
        .sprite { display: inline-block; width: 80px; height: 80px; background-size: cover; vertical-align: middle; }
        .hero-sprite { background-image: url('https://cdn.pixabay.com/photo/2013/07/13/12/07/knight-145440_1280.png'); }
        .boss-sprite { background-image: url('https://cdn.pixabay.com/photo/2014/04/03/10/32/monster-312822_1280.png'); transition: transform 0.2s; }
        .shake { animation: shake 0.4s; }
        @keyframes shake {
            0% { transform: translate(0, 0); }
            20% { transform: translate(-8px, 0); }
            40% { transform: translate(8px, 0); }
            60% { transform: translate(-8px, 0); }
            80% { transform: translate(8px, 0); }
            100% { transform: translate(0, 0); }
        }
        .flag { background: #e0ffe0; color: #008000; padding: 10px; border-radius: 5px; margin-top: 20px; font-weight: bold; opacity: 0; transition: opacity 1s; }
        .flag.show { opacity: 1; }
        .dot {
            position: absolute;
            border-radius: 50%;
            background: radial-gradient(circle at 30% 30%, #fff 0%, #b30000 80%);
            z-index: 10;
            pointer-events: none;
            opacity: 0.95;
            box-shadow: 0 0 8px #b30000;
            transition: box-shadow 0.2s;
        }
        .dot-boss {
            background: radial-gradient(circle at 30% 30%, #fff 0%, #0077b3 80%);
            box-shadow: 0 0 12px #0077b3;
        }
        .arena { position: relative; min-height: 120px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Hero vs Boss</h2>
        <div class="arena">
            <div class="hero" style="display:inline-block; width:48%; text-align:center; position:relative;">
                <span class="sprite hero-sprite" id="hero-sprite"></span>
                <div class="hpbar-bg"><div id="hero-bar" class="hpbar hpbar-hero" style="width:100%"></div></div>
                HP: <span id="hero-hp">100</span> / 100<br>
                Damage: <span id="hero-dmg">2</span>
            </div>
            <div class="boss" style="display:inline-block; width:48%; text-align:center; position:relative; float:right;">
                <span id="boss-sprite" class="sprite boss-sprite"></span>
                <div class="hpbar-bg"><div id="boss-bar" class="hpbar" style="width:100%"></div></div>
                HP: <span id="boss-hp">50</span> / 50
            </div>
        </div>
        <form id="attack-form" method="POST">
            <input type="hidden" name="encrypted_data" id="encrypted_data">
            <input type="hidden" name="hmac" id="hmac_data"> 
            <button class="btn" type="button" onclick="submitAttack()" >Serang Boss!</button>
        </form>
        <div id="result"></div>
                <div id="flag" class="flag">&nbsp;</div>
            </div>
    <script>
    function setBar(id, val, max) {
        var bar = document.getElementById(id);
        var pct = Math.max(0, Math.min(100, Math.round(val/max*100)));
        bar.style.width = pct + "%";
    }
    setBar('hero-bar', 100, 100);
    setBar('boss-bar', 50, 50);

    
    
    function animateDot(fromId, toId, dmg, isBoss) {
        var from = document.getElementById(fromId).getBoundingClientRect();
        var to = document.getElementById(toId).getBoundingClientRect();
        var arena = document.querySelector('.arena').getBoundingClientRect();
        var dot = document.createElement('div');
        dot.className = 'dot' + (isBoss ? ' dot-boss' : '');
        var size = Math.max(18, Math.min(60, Math.abs(dmg)));
        dot.style.width = size + 'px';
        dot.style.height = size + 'px';
        dot.style.left = (from.left + from.width/2 - arena.left - size/2) + 'px';
        dot.style.top = (from.top + from.height/2 - arena.top - size/2) + 'px';
        document.querySelector('.arena').appendChild(dot);
        setTimeout(function() {
            dot.style.transition = 'all 0.6s cubic-bezier(.68,-0.55,.27,1.55)';
            dot.style.left = (to.left + to.width/2 - arena.left - size/2) + 'px';
            dot.style.top = (to.top + to.height/2 - arena.top - size/2) + 'px';
        }, 10);
        setTimeout(function() {
            dot.remove();
        }, 700);
    }

    
    async function submitAttack() {
        let damageValue = 2; // Default damage
        const params = new URLSearchParams();
        params.append('damage', damageValue);
        const plainTextData = params.toString();

        const encryptedPayload = await encryptData(plainTextData);
        if (encryptedPayload) {
            const hmacSignature = await generateHmac(encryptedPayload); 
            if (hmacSignature) {
                document.getElementById('encrypted_data').value = encryptedPayload;
                document.getElementById('hmac_data').value = hmacSignature;
                document.getElementById('attack-form').submit();
            } else {
                alert("Gagal menghasilkan HMAC. Serangan dibatalkan.");
            }
        } else {
            alert("Gagal mengenkripsi data. Serangan dibatalkan.");
        }
    }

    if (window.history.replaceState) {
        window.history.replaceState(null, null, window.location.href);
    }
    </script>
</body>
</html> 
