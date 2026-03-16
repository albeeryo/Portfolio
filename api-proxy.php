<?php
/**
 * LucidFolio — CoinGecko API Proxy
 * Upload this file to: /Portfolio/api-proxy.php on sakrama.me
 *
 * This file keeps your CoinGecko API key hidden from the browser.
 * The HTML never sees the key — all requests go through here.
 */

// ── YOUR COINGECKO KEY — safe here, never sent to browser ──
define('CG_KEY', 'CG-vUyUd14raQgJohVNCfawiSUS');
define('CG_BASE', 'https://api.coingecko.com/api/v3');

// ── SECURITY: only allow requests from your own domain ──
$origin = $_SERVER['HTTP_HOST'] ?? '';
$allowed_origins = ['sakrama.me', 'www.sakrama.me', 'localhost'];

if (!in_array($origin, $allowed_origins, true)) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Forbidden']);
    exit;
}

// ── CORS headers — only allow your domain ──
header('Access-Control-Allow-Origin: https://sakrama.me');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Accept');

// ── Only allow GET ──
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// ── Validate the path param exists ──
$path = $_GET['path'] ?? '';
if (empty($path)) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Missing path']);
    exit;
}

// ── Whitelist: only allow these CoinGecko endpoints ──
$allowed_prefixes = [
    '/simple/price',
    '/coins/markets',
    '/coins/list',
    '/coins/bitcoin/market_chart',
    '/coins/ethereum/market_chart',
    '/coins/solana/market_chart',
    '/coins/binancecoin/market_chart',
    '/coins/cardano/market_chart',
    '/coins/ripple/market_chart',
    '/coins/dogecoin/market_chart',
    '/coins/polkadot/market_chart',
    '/coins/chainlink/market_chart',
    '/coins/avalanche-2/market_chart',
    '/coins/matic-network/market_chart',
    '/coins/litecoin/market_chart',
    '/coins/uniswap/market_chart',
    '/coins/stellar/market_chart',
    '/coins/cosmos/market_chart',
    '/coins/monero/market_chart',
    '/coins/ethereum-classic/market_chart',
    '/coins/vechain/market_chart',
    '/coins/filecoin/market_chart',
    '/coins/tron/market_chart',
    '/coins/shiba-inu/market_chart',
    '/coins/the-sandbox/market_chart',
    '/coins/decentraland/market_chart',
    '/coins/axie-infinity/market_chart',
    '/coins/aave/market_chart',
    '/coins/maker/market_chart',
    '/coins/compound-governance-token/market_chart',
    '/coins/internet-computer/market_chart',
    '/coins/near/market_chart',
    '/coins/fantom/market_chart',
    '/coins/algorand/market_chart',
    '/coins/elrond-erd-2/market_chart',
    '/coins/hedera-hashgraph/market_chart',
    '/coins/tezos/market_chart',
    '/coins/eos/market_chart',
    '/coins/iota/market_chart',
    '/coins/neo/market_chart',
    '/coins/dash/market_chart',
    '/coins/zcash/market_chart',
    '/coins/theta-token/market_chart',
    '/coins/terra-luna/market_chart',
    '/coins/kusama/market_chart',
    '/coins/flow/market_chart',
    '/coins/the-graph/market_chart',
    '/coins/basic-attention-token/market_chart',
    '/coins/1inch/market_chart',
];

// More flexible check: allow /coins/{any-id}/market_chart
$is_allowed = false;
foreach ($allowed_prefixes as $prefix) {
    if (strpos($path, $prefix) === 0) {
        $is_allowed = true;
        break;
    }
}
// Also allow any /coins/{id}/market_chart pattern
if (!$is_allowed && preg_match('#^/coins/[a-z0-9\-]+/market_chart#', $path)) {
    $is_allowed = true;
}

if (!$is_allowed) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Endpoint not allowed']);
    exit;
}

// ── Rate limit: max 60 requests per minute per IP ──
// Simple file-based rate limiter
$ip = md5($_SERVER['REMOTE_ADDR'] ?? 'unknown'); // hash IP for privacy
$rate_file = sys_get_temp_dir() . '/cg_rate_' . $ip . '.json';
$now = time();
$window = 60; // seconds
$max_requests = 60;

$rate_data = ['requests' => [], 'blocked_until' => 0];
if (file_exists($rate_file)) {
    $raw = file_get_contents($rate_file);
    if ($raw) $rate_data = json_decode($raw, true) ?: $rate_data;
}

// Check if blocked
if ($rate_data['blocked_until'] > $now) {
    http_response_code(429);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Rate limit exceeded. Try again in ' . ($rate_data['blocked_until'] - $now) . 's']);
    exit;
}

// Clean old requests outside the window
$rate_data['requests'] = array_filter($rate_data['requests'], fn($t) => $t > $now - $window);

// Check rate
if (count($rate_data['requests']) >= $max_requests) {
    $rate_data['blocked_until'] = $now + $window;
    file_put_contents($rate_file, json_encode($rate_data));
    http_response_code(429);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Rate limit exceeded']);
    exit;
}

// Log this request
$rate_data['requests'][] = $now;
file_put_contents($rate_file, json_encode($rate_data));

// ── Build the real CoinGecko URL with the secret key ──
$sep = str_contains($path, '?') ? '&' : '?';
$cg_url = CG_BASE . $path . $sep . 'x_cg_demo_api_key=' . CG_KEY;

// ── Make the request to CoinGecko ──
$ch = curl_init($cg_url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 10,
    CURLOPT_HTTPHEADER     => [
        'accept: application/json',
        'x-cg-demo-api-key: ' . CG_KEY,
    ],
    CURLOPT_FOLLOWLOCATION => false, // don't follow redirects
    CURLOPT_SSL_VERIFYPEER => true,  // always verify SSL
]);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curl_error = curl_error($ch);
curl_close($ch);

if ($curl_error || $response === false) {
    http_response_code(502);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Upstream request failed']);
    exit;
}

// ── Return the response ──
http_response_code($http_code);
header('Content-Type: application/json');
header('Cache-Control: public, max-age=30'); // cache price data 30s
echo $response;
