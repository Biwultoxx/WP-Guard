<?php
declare(strict_types=1);
session_start();

$cfgPath = '/etc/wpdbdash/config.php';
if (!file_exists($cfgPath)) { http_response_code(500); echo "Missing config"; exit; }
$cfg = require $cfgPath;

/* -------------------- Helpers -------------------- */
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function q_ident(string $name): string { return '`' . str_replace('`', '``', $name) . '`'; }
function hex_rand(int $bytes): string { return bin2hex(random_bytes($bytes)); }

function csrf_token(): string {
  if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
  return $_SESSION['csrf'];
}
function check_csrf(): void {
  $t = $_POST['csrf'] ?? '';
  if (!is_string($t) || empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $t)) {
    http_response_code(400); echo "CSRF invalid"; exit;
  }
}
function require_login(): void {
  if (!isset($_SESSION['ok']) || $_SESSION['ok'] !== true) {
    header("Location: ?login=1"); exit;
  }
}
function pdo_mysql(array $cfg): PDO {
  $dsn = "mysql:host={$cfg['mysql_host']};port={$cfg['mysql_port']};charset=utf8mb4";
  return new PDO($dsn, $cfg['mysql_user'], $cfg['mysql_pass'], [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
  ]);
}

function browse_prefix(array $cfg): string { return (string)($cfg['browse_db_prefix'] ?? ''); }
function is_allowed_db(array $cfg, string $db): bool {
  $prefix = browse_prefix($cfg);
  return $prefix === '' ? true : str_starts_with($db, $prefix);
}
function url_with(array $add): string {
  $q = $_GET;
  foreach ($add as $k=>$v) {
    if ($v === null) unset($q[$k]);
    else $q[$k] = $v;
  }
  return '?' . http_build_query($q);
}

/* -------------------- History helpers -------------------- */
function history_read(string $file): array {
  if (!file_exists($file)) return [];
  $raw = file_get_contents($file);
  if ($raw === false || trim($raw) === '') return [];
  $data = json_decode($raw, true);
  return is_array($data) ? $data : [];
}
function history_write(string $file, array $data): void {
  $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
  if ($json !== false) file_put_contents($file, $json, LOCK_EX);
}
function history_append(string $file, array $row): void {
  $data = history_read($file);
  $data[] = $row;
  history_write($file, $data);
}
function history_find_creds_for_db(array $history, string $dbName): array {
  for ($i = count($history)-1; $i >= 0; $i--) {
    $r = $history[$i] ?? [];
    if (($r['db_name'] ?? '') === $dbName) {
      $u = (string)($r['db_user'] ?? '');
      $h = (string)($r['user_host'] ?? '');
      return ($u !== '') ? ['db_user'=>$u, 'user_host'=>$h] : [];
    }
  }
  return [];
}
function history_remove_db(array $history, string $dbName): array {
  return array_values(array_filter($history, fn($r) => ($r['db_name'] ?? '') !== $dbName));
}
function guard_service_name(string $db): string {
    return "wp-guard-" . $db;
}
function detect_wp_prefix(mysqli $db): string {

    $res = $db->query("
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        AND table_name LIKE '%users'
        LIMIT 1
    ");

    if (!$res || $res->num_rows == 0) return 'wp_';

    $row = $res->fetch_assoc();
    $table = $row['table_name'];

    return str_replace('users','',$table);
}

function guard_install(array $cfg, string $db): string {

    $g = $cfg['wp_guard'];
    $root = rtrim($g['install_root'],'/');
    $interval = max(2, (int)$g['interval']);

    $svc = guard_service_name($db);
    $path = "$root/$db";

    if (!is_dir($path)) {
        if (!mkdir($path,0755,true)) {
            return "Failed create guard dir";
        }
    }

    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

    try {
        $mysqli = new mysqli(
            $cfg['mysql_host'],
            $cfg['mysql_user'],
            $cfg['mysql_pass'],
            $db
        );
    } catch(Throwable $e){
        return "DB connect fail";
    }

    $prefix = detect_wp_prefix($mysqli);

    $users = $prefix.'users';
    $meta  = $prefix.'usermeta';

    $check = $mysqli->query("SHOW TABLES LIKE '$users'");
    if($check->num_rows === 0){
        return "Not wordpress db";
    }

    $snapshot = "$path/snapshot.sql";
    $hashfile = "$path/hash.txt";

    $pass = escapeshellarg($cfg['mysql_pass']);

    $dumpCmd = sprintf(
        '/usr/bin/mysqldump --single-transaction --quick --skip-lock-tables --skip-add-locks --no-create-info -h%s -u%s --password=%s %s %s %s > %s 2>&1',
        escapeshellarg($cfg['mysql_host']),
        escapeshellarg($cfg['mysql_user']),
        escapeshellarg($cfg['mysql_pass']),
        escapeshellarg($db),
        escapeshellarg($users),
        escapeshellarg($meta),
        escapeshellarg($snapshot)
    );

exec($dumpCmd, $out, $code);

file_put_contents("/tmp/wpguard_dump_debug.txt", implode("\n",$out));

if ($code !== 0 || !file_exists($snapshot) || filesize($snapshot) < 1000) {
    return "SNAPSHOT FAILED: " . implode("\n",$out);
}

    $hash = hash_file('sha256',$snapshot);
    file_put_contents($hashfile,$hash);

      $monitor = <<<'PHP'
        <?php
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

        $dbname = "__DB__";
        $users = "__USERS__";
        $meta = "__META__";
        $cap = "__CAP__";
        $lvl = "__LVL__";

        $snapshot = "__SNAP__";
        $hashfile = "__HASH__";

        $db = new mysqli("__HOST__","__USER__","__PASS__",$dbname);
        $db->set_charset("utf8mb4");

        function wpguard_hash($db,$users,$meta,$cap,$lvl){

            $data="";

            $r1=$db->query("
                SELECT ID,user_login,user_pass,user_email
                FROM $users
                ORDER BY ID
            ");
            while($r=$r1->fetch_assoc())
                $data.=json_encode($r);

            $r2=$db->query("
                SELECT user_id,meta_key,meta_value
                FROM $meta
                WHERE meta_key IN ('$cap','$lvl')
                ORDER BY user_id, meta_key
            ");
            while($r=$r2->fetch_assoc())
                $data.=json_encode($r);

            return hash('sha256',$data);
        }

        if(!file_exists($hashfile) || !file_exists($snapshot)) exit;

        $current = wpguard_hash($db,$users,$meta,$cap,$lvl);
        $saved = trim(file_get_contents($hashfile));

        if($current !== $saved){

            $db->query("SET FOREIGN_KEY_CHECKS=0");

            $db->query("SET FOREIGN_KEY_CHECKS=0");
            $db->query("TRUNCATE TABLE `$users`");
            $db->query("TRUNCATE TABLE `$meta`");
            $db->query("SET FOREIGN_KEY_CHECKS=1");

            $cmd = sprintf(
                '/usr/bin/mysql -h%s -u%s --password=%s %s < %s',
                "__HOST__",
                "__USER__",
                "__PASS__",
                $dbname,
                $snapshot
            );

            exec($cmd,$o,$code);

            $db->query("SET FOREIGN_KEY_CHECKS=1");

            if($code === 0){
                $new = wpguard_hash($db,$users,$meta,$cap,$lvl);
                file_put_contents($hashfile,$new);
            }
        }
        PHP;

        $cap = $prefix . 'capabilities';
        $lvl = $prefix . 'user_level';

        $monitor = str_replace([
        "__DB__",
        "__USERS__",
        "__META__",
        "__CAP__",
        "__LVL__",
        "__SNAP__",
        "__HASH__",
        "__HOST__",
        "__USER__",
        "__PASS__"
        ],[
        $db,
        $users,
        $meta,
        $cap,
        $lvl,
        $snapshot,
        $hashfile,
        $cfg['mysql_host'],
        $cfg['mysql_user'],
        $cfg['mysql_pass']
        ], $monitor);

    file_put_contents("$path/monitor.php",$monitor);

    $worker = <<<BASH
      #!/bin/bash
      exec 9>/tmp/wpguard-$db.lock
      flock -n 9 || exit 1

      while true
      do
      /usr/bin/php $path/monitor.php
      sleep $interval
      done
      BASH;

    file_put_contents("$path/worker.sh",$worker);
    chmod("$path/worker.sh",0755);

    $out = shell_exec("sudo /usr/local/bin/wpguardctl install " . escapeshellarg($db) . " 2>&1");
    file_put_contents("/tmp/wpguard_debug.txt", $out);

    /* AUTO FIX SYSTEMD */
    shell_exec("sudo systemctl daemon-reload");
    shell_exec("sudo systemctl reset-failed");
    shell_exec("sudo systemctl enable wp-guard-$db");
    shell_exec("sudo systemctl restart wp-guard-$db");

    return "Immutable guard enabled ($db)";
    }

    function guard_remove(array $cfg, string $db): string {

        shell_exec("sudo /usr/local/bin/wpguardctl remove " . escapeshellarg($db));

        shell_exec("systemctl daemon-reload");
        shell_exec("systemctl reset-failed");

        return "Guard disabled ($db)";
    }

    function guard_status(string $db): bool {

        $svc = guard_service_name($db);

        exec("systemctl is-active --quiet $svc", $o, $code);

        return $code === 0;
    }
/* -------------------- State -------------------- */
$err = null;
$msg = null;
$created = null;

/* -------------------- Login page -------------------- */
if (isset($_GET['login'])) {
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['u'] ?? '';
    $p = $_POST['p'] ?? '';
    if (is_string($u) && is_string($p)
        && hash_equals((string)$cfg['admin_user'], $u)
        && hash_equals((string)$cfg['admin_pass'], $p)) {
      $_SESSION['ok'] = true;
      csrf_token();
      header("Location: ?"); exit;
    } else $err = "Login gagal.";
  }
  ?>
  <!doctype html>
  <html>
  <head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Login - WP DB Dashboard</title>
    <style>
      :root{
        --bg:#070c18;
        --panel:#0e1630;
        --panel2:#0b1226;
        --border:#22304d;
        --text:#eaf0ff;
        --muted:#a9b6d3;
        --bad:#ff7070;
        --ok:#3ddc97;
        --link:#8ab4ff;
        --shadow: 0 20px 60px rgba(0,0,0,.45);
        --radius: 18px;
      }
      *{box-sizing:border-box}
      body{
        margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
        background: radial-gradient(1000px 600px at 20% 10%, rgba(138,180,255,.18), transparent 60%),
                    radial-gradient(900px 500px at 80% 90%, rgba(61,220,151,.12), transparent 55%),
                    var(--bg);
        color:var(--text);
        min-height:100vh;
        display:grid;
        place-items:center;
        padding:22px;
      }
      a{color:var(--link);text-decoration:none}
      a:hover{text-decoration:underline}
      .card{
        width:min(520px, 94vw);
        background: linear-gradient(180deg, rgba(255,255,255,.03), transparent 30%), var(--panel);
        border:1px solid var(--border);
        border-radius:var(--radius);
        box-shadow: var(--shadow);
        padding:20px;
      }
      .head{display:flex;align-items:center;justify-content:space-between;gap:12px}
      .title{display:flex;flex-direction:column;gap:4px}
      h1{font-size:18px;margin:0}
      .muted{color:var(--muted);font-size:13px;line-height:1.5}
      .badge{
        font-size:12px; color:var(--muted);
        border:1px solid var(--border);
        background: rgba(29,42,70,.55);
        padding:6px 10px;
        border-radius:999px;
        white-space:nowrap;
      }
      form{margin-top:14px}
      label{display:block;font-size:12px;color:var(--muted);margin:10px 0 6px}
      .input{
        width:100%;
        padding:12px 12px;
        border-radius:14px;
        border:1px solid var(--border);
        background: var(--panel2);
        color: var(--text);
        outline: none;
      }
      .input:focus{border-color:#355aa8; box-shadow:0 0 0 3px rgba(138,180,255,.15)}
      .row{display:flex;gap:10px;align-items:center}
      .btn{
        width:100%;
        margin-top:12px;
        padding:12px 14px;
        border-radius:14px;
        border:1px solid var(--border);
        background: linear-gradient(180deg, rgba(138,180,255,.16), rgba(138,180,255,.06)), #0b1535;
        color:var(--text);
        cursor:pointer;
        font-weight:600;
      }
      .btn:hover{filter:brightness(1.06)}
      .err{
        border:1px solid rgba(255,112,112,.35);
        background: rgba(255,112,112,.08);
        color: var(--bad);
        padding:10px 12px;
        border-radius:14px;
        margin-top:12px;
      }
      .foot{
        margin-top:12px;
        padding-top:12px;
        border-top:1px solid var(--border);
        display:flex;
        justify-content:space-between;
        gap:10px;
        flex-wrap:wrap;
      }
      .toggle{
        display:flex;align-items:center;gap:8px;
        font-size:13px;color:var(--muted);
        user-select:none;
      }
      .toggle input{accent-color: var(--ok)}
      code{background:#0e162b;border:1px solid var(--border);padding:2px 8px;border-radius:10px;color:var(--text)}
    </style>
    <script>
      function togglePass(){
        const el = document.getElementById('p');
        el.type = (el.type === 'password') ? 'text' : 'password';
      }
    </script>
  </head>
  <body>
    <div class="card">
      <div class="head">
        <div class="title">
          <h1>WP DB Dashboard</h1>
          <div class="muted">Generate database & user WordPress, plus viewer table.</div>
        </div>
        <div class="badge">Secure Admin</div>
      </div>

      <?php if($err): ?><div class="err"><?=h($err)?></div><?php endif; ?>

      <form method="post" autocomplete="off">
        <label>Username</label>
        <input class="input" name="u" placeholder="admin" autocomplete="username" required>

        <label>Password</label>
        <input class="input" id="p" name="p" placeholder="••••••••" type="password" autocomplete="current-password" required>

        <div class="foot">
          <label class="toggle"><input type="checkbox" onclick="togglePass()"> Show password</label>
          <div class="muted">Hint: pakai BasicAuth / VPN untuk akses.</div>
        </div>

        <button class="btn" type="submit">Login</button>
      </form>
    </div>
  </body>
  </html>
  <?php exit;
}

if (isset($_GET['logout'])) { session_destroy(); header("Location: ?login=1"); exit; }
require_login();

/* -------------------- Load history -------------------- */
$historyFile = (string)($cfg['history_file'] ?? '');
$history = $historyFile ? history_read($historyFile) : [];

/* -------------------- Actions -------------------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $action = (string)($_POST['action'] ?? '');

  if ($action === 'create') {
    check_csrf();
    try {
      $pdo = pdo_mysql($cfg);

      $dbName = (string)$cfg['db_name_prefix'] . hex_rand((int)$cfg['name_rand_bytes']);
      $dbUser = (string)$cfg['db_user_prefix'] . hex_rand((int)$cfg['name_rand_bytes']);
      $dbPass = hex_rand((int)$cfg['pass_rand_bytes']);
      $dbUser = substr($dbUser, 0, 32);

      $userHost = (string)($cfg['grant_host'] ?? '%');
      $userHostSql = $pdo->quote($userHost);

      $pdo->exec("CREATE DATABASE " . q_ident($dbName) . " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");

      $stmt = $pdo->prepare("CREATE USER " . q_ident($dbUser) . "@{$userHostSql} IDENTIFIED BY ?");
      $stmt->execute([$dbPass]);

      $pdo->exec(
        "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP
         ON " . q_ident($dbName) . ".* TO " . q_ident($dbUser) . "@{$userHostSql}"
      );

      $wpHost = (string)($cfg['wp_db_host'] ?? $cfg['mysql_host']);
      $wpPort = (int)($cfg['wp_db_port'] ?? $cfg['mysql_port']);

      $created = [
        'WP_DB_HOST'   => $wpHost . ':' . $wpPort,
        'DB_NAME'      => $dbName,
        'DB_USER'      => $dbUser,
        'DB_PASS'      => $dbPass,
        'DB_USER_HOST' => $userHost,
      ];
      $msg = "Berhasil membuat DB + user + password.";

      if ($historyFile) {
        history_append($historyFile, [
          'created_at' => date('c'),
          'db_name'    => $dbName,
          'db_user'    => $dbUser,
          'db_pass'    => $dbPass,
          'user_host'  => $userHost,
          'wp_db_host' => $wpHost,
          'wp_db_port' => $wpPort,
        ]);
        $history = history_read($historyFile);
      }
    } catch (Throwable $e) {
      $err = $e->getMessage();
    }

  } elseif ($action === 'guard_on') {
    check_csrf();
    $msg = guard_install($cfg, $_POST['db_name']);

  } elseif ($action === 'guard_off') {
    check_csrf();
    $msg = guard_remove($cfg, $_POST['db_name']);

  } elseif ($action === 'delete_db') {
    check_csrf();
    $db = (string)($_POST['db_name'] ?? '');
    $confirm = (string)($_POST['confirm'] ?? '');

    if ($db === '' || $confirm !== 'YES') {
      $err = "Delete dibatalkan (confirm tidak valid).";
    } elseif (!is_allowed_db($cfg, $db)) {
      $err = "DB tidak diizinkan untuk dihapus.";
    } else {
      try {
          $pdo = pdo_mysql($cfg);

          $creds = history_find_creds_for_db($history, $db);
          $userToDrop = (string)($creds['db_user'] ?? '');
          $userHost   = (string)($creds['user_host'] ?? ($cfg['grant_host'] ?? '%'));
          $userHostSql = $pdo->quote($userHost);

          // 🔥 STOP GUARD SERVICE DULU
          shell_exec("sudo /usr/local/bin/wpguardctl remove " . escapeshellarg($db));

          // 🔥 HAPUS DIR GUARD
          $guardDir = rtrim($cfg['wp_guard']['install_root'],'/') . "/$db";
          if (is_dir($guardDir)) {
              shell_exec("rm -rf " . escapeshellarg($guardDir));
          }

          // 🔥 DROP DATABASE
          $pdo->exec("DROP DATABASE IF EXISTS " . q_ident($db));

          // 🔥 DROP USER
          if ($userToDrop !== '') {
              $pdo->exec("DROP USER IF EXISTS " . q_ident($userToDrop) . "@{$userHostSql}");
          }

          // 🔥 UPDATE HISTORY
          if ($historyFile) {
              $history = history_remove_db($history, $db);
              history_write($historyFile, $history);
          }

          $msg = "DB $db + guard dir + service berhasil dihapus.";

          $_GET['db'] = '';
          $_GET['table'] = '';

      } catch (Throwable $e) {
          $err = $e->getMessage();
      }
    }
  }
}

/* -------------------- Browse: DB / table / data -------------------- */
$viewDb = isset($_GET['db']) && is_string($_GET['db']) ? $_GET['db'] : '';
$viewTable = isset($_GET['table']) && is_string($_GET['table']) ? $_GET['table'] : '';

$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$limitDefault = (int)($cfg['row_limit'] ?? 50);
$limitMax = (int)($cfg['max_row_limit'] ?? 200);
$limit = isset($_GET['limit']) ? (int)$_GET['limit'] : $limitDefault;
$limit = max(1, min($limit, $limitMax));
$offset = ($page - 1) * $limit;

$searchCol = isset($_GET['col']) && is_string($_GET['col']) ? $_GET['col'] : '';
$searchVal = isset($_GET['q']) && is_string($_GET['q']) ? trim($_GET['q']) : '';

$dbList = []; $tableList = []; $columns = []; $rows = []; $totalRows = null;

try {
  $pdo = pdo_mysql($cfg);

  foreach ($pdo->query("SHOW DATABASES")->fetchAll() as $r) {
    $d = (string)$r['Database'];
    if (is_allowed_db($cfg, $d)) $dbList[] = $d;
  }
  sort($dbList);

  if ($viewDb !== '' && !in_array($viewDb, $dbList, true)) { $viewDb = ''; $viewTable = ''; }

  if ($viewDb !== '') {
    $pdo->exec("USE " . q_ident($viewDb));
    $tableList = array_map(fn($x) => (string)$x[0], $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_NUM));
    sort($tableList);

    if ($viewTable !== '' && !in_array($viewTable, $tableList, true)) $viewTable = '';

    if ($viewTable !== '') {
      $desc = $pdo->query("DESCRIBE " . q_ident($viewTable))->fetchAll();
      $columns = array_map(fn($x) => (string)$x['Field'], $desc);

      $countSql = "SELECT COUNT(*) AS c FROM " . q_ident($viewTable);
      $params = [];
      if ($searchCol !== '' && $searchVal !== '' && in_array($searchCol, $columns, true)) {
        $countSql .= " WHERE " . q_ident($searchCol) . " LIKE ?";
        $params[] = '%' . $searchVal . '%';
      }
      $stCount = $pdo->prepare($countSql);
      $stCount->execute($params);
      $totalRows = (int)$stCount->fetch()['c'];

      $sql = "SELECT * FROM " . q_ident($viewTable);
      $params = [];
      if ($searchCol !== '' && $searchVal !== '' && in_array($searchCol, $columns, true)) {
        $sql .= " WHERE " . q_ident($searchCol) . " LIKE ?";
        $params[] = '%' . $searchVal . '%';
      }
      $sql .= " LIMIT {$limit} OFFSET {$offset}";
      $st = $pdo->prepare($sql);
      $st->execute($params);
      $rows = $st->fetchAll();
    }
  }
} catch (Throwable $e) { $err = $e->getMessage(); }

$historyNewestFirst = array_reverse($history);
$maxPage = ($totalRows === null || $totalRows === 0) ? 1 : (int)ceil($totalRows / $limit);
$prev = max(1, $page - 1);
$next = min($maxPage, $page + 1);

$mapped = ($viewDb !== '') ? history_find_creds_for_db($history, $viewDb) : [];
$mappedUser = (string)($mapped['db_user'] ?? '');
$mappedHost = (string)($mapped['user_host'] ?? '');

/* -------------------- HTML -------------------- */
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>WP DB Dashboard</title>
  <style>
    :root{
      --bg:#070c18;
      --panel:#0e1630;
      --panel2:#0b1226;
      --border:#22304d;
      --text:#eaf0ff;
      --muted:#a9b6d3;
      --ok:#3ddc97;
      --bad:#ff7070;
      --link:#8ab4ff;
      --shadow: 0 20px 60px rgba(0,0,0,.45);
      --radius: 18px;
      --radius2: 14px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(1200px 800px at 15% 10%, rgba(138,180,255,.16), transparent 55%),
                  radial-gradient(1000px 600px at 85% 90%, rgba(61,220,151,.10), transparent 60%),
                  var(--bg);
      color:var(--text);
    }
    a{color:var(--link);text-decoration:none}
    a:hover{text-decoration:underline}
    .layout{display:grid;grid-template-columns:340px 1fr;min-height:100vh}
    .side{
      background: linear-gradient(180deg, rgba(255,255,255,.03), transparent 30%), var(--panel);
      border-right:1px solid var(--border);
      padding:16px;
      overflow:auto;
    }
    .main{padding:18px; overflow:auto}
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.03), transparent 30%), var(--panel);
      border:1px solid var(--border);
      border-radius:var(--radius);
      padding:14px;
      box-shadow: 0 10px 30px rgba(0,0,0,.22);
      margin-bottom:14px;
    }
    .card h2{font-size:14px;margin:0 0 10px 0;color:#dbe6ff}
    .muted{color:var(--muted);font-size:13px;line-height:1.45}
    .brand{
      display:flex;align-items:center;justify-content:space-between;gap:10px;
      padding:12px 12px;
      border:1px solid var(--border);
      background: rgba(11,18,38,.55);
      border-radius:var(--radius);
      margin-bottom:14px;
      box-shadow: var(--shadow);
    }
    .brand .t{display:flex;flex-direction:column;gap:2px}
    .brand h1{font-size:16px;margin:0}
    .badge{
      font-size:12px; color:var(--muted);
      border:1px solid var(--border);
      background: rgba(29,42,70,.55);
      padding:6px 10px;
      border-radius:999px;
      white-space:nowrap;
    }
    .topbar{
      display:flex;align-items:center;justify-content:space-between;gap:10px;
      margin-bottom:14px;
      padding:12px 14px;
      border:1px solid var(--border);
      border-radius:var(--radius);
      background: rgba(11,18,38,.55);
      box-shadow: var(--shadow);
    }
    .topbar .left{display:flex;flex-direction:column;gap:2px}
    .topbar .right{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    .btn, button, input, select{
      background: var(--panel2);
      color: var(--text);
      border:1px solid var(--border);
      border-radius:var(--radius2);
      padding:10px 12px;
      font-size:14px;
    }
    button{cursor:pointer}
    .btn-primary{
      background: linear-gradient(180deg, rgba(138,180,255,.18), rgba(138,180,255,.06)), #0b1535;
      font-weight:600;
    }
    .btn-primary:hover{filter:brightness(1.06)}
    .btn-danger{
      border-color:#6b2b2b;
      background: linear-gradient(180deg, rgba(255,112,112,.18), rgba(255,112,112,.06)), #251018;
      font-weight:700;
    }
    .btn-danger:hover{filter:brightness(1.06)}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
    .pill{
      display:flex;align-items:center;justify-content:space-between;gap:10px;
      padding:10px 12px;border:1px solid var(--border);border-radius:var(--radius2);
      background: rgba(11,18,38,.55);
    }
    .pill.active{outline:2px solid rgba(138,180,255,.28)}
    .list{margin:0;padding:0;list-style:none}
    .list li{margin:8px 0}
    code, pre{
      background:#0b1530;
      border:1px solid var(--border);
      border-radius:var(--radius2);
      color:var(--text);
    }
    code{padding:2px 8px}
    pre{padding:12px;overflow:auto}
    .hr{height:1px;background:var(--border);margin:12px 0}
    .alert{
      border-left:4px solid var(--border);
      padding:12px 12px;
    }
    .ok{border-left-color:var(--ok)}
    .bad{border-left-color:var(--bad)}
    .scroll{
      max-height:62vh;overflow:auto;border:1px solid var(--border);
      border-radius:var(--radius); background: rgba(11,18,38,.35);
    }
    table{width:100%;border-collapse:separate;border-spacing:0}
    th,td{border-bottom:1px solid var(--border);padding:10px 10px;vertical-align:top}
    th{
      position:sticky;top:0;z-index:1;text-align:left;
      background: rgba(14,22,48,.96);
      backdrop-filter: blur(6px);
    }
    tbody tr:nth-child(even){background: rgba(255,255,255,.02)}
    td{
      max-width:560px;
      overflow:hidden;
      text-overflow:ellipsis;
      white-space:nowrap;
    }
    td.wrap{
      white-space:normal;
      word-break:break-word;
      max-width:720px;
    }
    .small{font-size:12px;color:var(--muted)}
    @media (max-width: 1100px){
      .layout{grid-template-columns:1fr}
      .side{border-right:none;border-bottom:1px solid var(--border)}
      .grid{grid-template-columns:1fr}
      td{max-width:360px}
    }
  </style>
  <script>
    function confirmDelete(dbName){
      const ok = prompt("Ketik YES untuk hapus DB: " + dbName);
      if(ok !== "YES") return false;
      document.getElementById("confirm").value = "YES";
      return true;
    }
    function copyText(id){
      const el = document.getElementById(id);
      if(!el) return;
      navigator.clipboard.writeText(el.innerText || el.textContent || "");
      alert("Copied");
    }
    function toggleWrap(){
      const table = document.getElementById('dataTable');
      if(!table) return;
      const wrap = table.getAttribute('data-wrap') === '1';
      table.setAttribute('data-wrap', wrap ? '0':'1');
      const tds = table.querySelectorAll('td');
      tds.forEach(td => {
        if (wrap) td.classList.remove('wrap');
        else td.classList.add('wrap');
      });
    }
  </script>
</head>
<body>
  <div class="layout">
    <aside class="side">
      <div class="brand">
        <div class="t">
          <h1>WP DB Dashboard</h1>
          <div class="muted">DB generator + viewer</div>
        </div>
        <span class="badge">Logged in</span>
      </div>

      <div class="card">
        <h2>Quick</h2>
        <div class="row" style="justify-content:space-between">
          <a href="<?=h(url_with(['db'=>null,'table'=>null,'page'=>null,'col'=>null,'q'=>null]))?>">Home</a>
          <a href="?logout=1">Logout</a>
        </div>
        <div class="muted" style="margin-top:10px">
          Browse prefix: <code><?=h(browse_prefix($cfg))?></code>
        </div>
      </div>

      <div class="card">
        <h2>Databases</h2>
        <?php if(!$dbList): ?>
          <div class="muted">Tidak ada DB.</div>
        <?php else: ?>
          <ul class="list">
            <?php foreach($dbList as $d): ?>
              <?php $active = ($viewDb === $d); ?>
              <li>
                <div class="pill <?= $active ? 'active' : '' ?>">
                  <a href="<?=h(url_with(['db'=>$d,'table'=>null,'page'=>1,'col'=>null,'q'=>null]))?>"><?=h($d)?></a>
                  <span class="small"><?= $active ? 'selected' : '' ?></span>
                </div>
              </li>
            <?php endforeach; ?>
          </ul>
        <?php endif; ?>
      </div>

      <?php if($viewDb !== ''): ?>
      <div class="card">
        <h2>Tables</h2>
        <?php if(!$tableList): ?>
          <div class="muted">Belum ada table.</div>
        <?php else: ?>
          <ul class="list">
            <?php foreach($tableList as $t): ?>
              <?php $active = ($viewTable === $t); ?>
              <li>
                <div class="pill <?= $active ? 'active' : '' ?>">
                  <a href="<?=h(url_with(['db'=>$viewDb,'table'=>$t,'page'=>1,'col'=>null,'q'=>null]))?>"><?=h($t)?></a>
                  <span class="small"><?= $active ? 'open' : '' ?></span>
                </div>
              </li>
            <?php endforeach; ?>
          </ul>
        <?php endif; ?>
      </div>
      <?php endif; ?>
    </aside>

    <main class="main">
      <div class="topbar">
        <div class="left">
          <div style="font-weight:700">Dashboard</div>
          <div class="muted">Generate DB/user, browse table, dan delete DB (prefix-only).</div>
        </div>
        <div class="right">
          <span class="muted">Grant host:</span> <code><?=h((string)($cfg['grant_host'] ?? '%'))?></code>
          <span class="muted">WP DB:</span> <code><?=h((string)($cfg['wp_db_host'] ?? 'unset'))?></code>
        </div>
      </div>

      <?php if($msg): ?><div class="card alert ok"><?=h($msg)?></div><?php endif; ?>
      <?php if($err): ?><div class="card alert bad"><?=h($err)?></div><?php endif; ?>

      <div class="grid">
        <div class="card">
          <h2>Generate</h2>
          <form method="post" class="row">
            <input type="hidden" name="action" value="create">
            <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
            <button class="btn-primary" type="submit">Generate & Create</button>
            <span class="muted">Prefix tabel WordPress ditentukan saat setup WordPress.</span>
          </form>

          <?php if($created): ?>
            <div class="hr"></div>
            <div class="muted">Credentials:</div>
            <pre><code id="creds"><?php foreach($created as $k=>$v){ echo h($k).": ".h((string)$v)."\n"; } ?></code></pre>
            <div class="row">
              <button type="button" onclick="copyText('creds')">Copy credentials</button>
            </div>

            <div class="muted" style="margin-top:10px">wp-config.php snippet:</div>
            <pre><code id="wpsnip">define('DB_NAME', '<?=h($created['DB_NAME'])?>');
define('DB_USER', '<?=h($created['DB_USER'])?>');
define('DB_PASSWORD', '<?=h($created['DB_PASS'])?>');
define('DB_HOST', '<?=h($created['WP_DB_HOST'])?>');</code></pre>
            <div class="row">
              <button type="button" onclick="copyText('wpsnip')">Copy wp-config snippet</button>
            </div>
            <div class="muted" style="margin-top:8px">
              User dibuat sebagai <code><?=h($created['DB_USER'])?>@<?=h($created['DB_USER_HOST'])?></code>
            </div>
          <?php endif; ?>
        </div>

        <div class="card">
          <h2>Danger Zone</h2>
          <?php if($viewDb === ''): ?>
            <div class="muted">Pilih database di sidebar untuk tombol delete.</div>
          <?php else: ?>
          <?php $gstatus = guard_status($viewDb); ?>

            <div style="margin-top:15px">

            <?php if(!$gstatus): ?>
            <form method="post">
            <input type="hidden" name="action" value="guard_on">
            <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
            <input type="hidden" name="db_name" value="<?=h($viewDb)?>">
            <button class="btn-primary">Enable WP Guard</button>
            </form>
            <?php else: ?>
            <form method="post">
            <input type="hidden" name="action" value="guard_off">
            <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
            <input type="hidden" name="db_name" value="<?=h($viewDb)?>">
            <button class="btn-danger">Disable WP Guard</button>
            </form>
            <?php endif; ?>

            </div>
            <?php
              $mapped = history_find_creds_for_db($history, $viewDb);
              $mappedUser = (string)($mapped['db_user'] ?? '');
              $mappedHost = (string)($mapped['user_host'] ?? '');
              $displayHost = $mappedHost ?: (string)($cfg['grant_host'] ?? '%');
            ?>
            <div class="muted">Database:</div>
            <div class="row" style="margin:8px 0">
              <code><?=h($viewDb)?></code>
              <?php if($mappedUser !== ''): ?>
                <span class="muted">User:</span> <code><?=h($mappedUser)?>@<?=h($displayHost)?></code>
              <?php else: ?>
                <span class="muted">(user tidak ada di history)</span>
              <?php endif; ?>
            </div>

            <form method="post" onsubmit="return confirmDelete('<?=h($viewDb)?>');">
              <input type="hidden" name="action" value="delete_db">
              <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
              <input type="hidden" name="db_name" value="<?=h($viewDb)?>">
              <input type="hidden" id="confirm" name="confirm" value="">
              <button class="btn-danger" type="submit">Delete DB<?= $mappedUser !== '' ? ' + User' : '' ?></button>
              <div class="muted" style="margin-top:10px">
                Ini menghapus <b>database</b><?= $mappedUser !== '' ? ' dan <b>user DB</b> (dari history)' : '' ?>.
              </div>
            </form>
          <?php endif; ?>
        </div>
      </div>

      <div class="card">
        <h2>Viewer</h2>
        <?php if($viewDb === ''): ?>
          <div class="muted">Pilih database di sidebar untuk melihat tabel & data.</div>
        <?php elseif($viewTable === ''): ?>
          <div class="muted">Pilih table di sidebar untuk melihat data.</div>
        <?php else: ?>
          <div class="row" style="justify-content:space-between">
            <div>
              <span class="muted">DB:</span> <code><?=h($viewDb)?></code>
              <span class="muted">Table:</span> <code><?=h($viewTable)?></code>
            </div>

            <form method="get" class="row">
              <input type="hidden" name="db" value="<?=h($viewDb)?>">
              <input type="hidden" name="table" value="<?=h($viewTable)?>">
              <input type="hidden" name="page" value="1">

              <select name="col">
                <option value="">(kolom)</option>
                <?php foreach($columns as $c): ?>
                  <option value="<?=h($c)?>" <?= $searchCol===$c ? 'selected':'' ?>><?=h($c)?></option>
                <?php endforeach; ?>
              </select>

              <input name="q" value="<?=h($searchVal)?>" placeholder="search (LIKE)">
              <select name="limit">
                <?php foreach([25,50,100,200] as $l): ?>
                  <?php if($l > $limitMax) continue; ?>
                  <option value="<?=$l?>" <?= $limit===$l?'selected':'' ?>><?=$l?>/page</option>
                <?php endforeach; ?>
              </select>

              <button class="btn" type="submit">Apply</button>
              <button class="btn" type="button" onclick="toggleWrap()">Wrap</button>
              <a class="muted" href="<?=h(url_with(['page'=>1,'col'=>null,'q'=>null]))?>">Reset</a>
            </form>
          </div>

          <?php
            $maxPage = ($totalRows === null || $totalRows === 0) ? 1 : (int)ceil($totalRows / $limit);
            $prev = max(1, $page - 1);
            $next = min($maxPage, $page + 1);
          ?>
          <div class="muted" style="margin-top:8px">
            Total: <b><?= $totalRows === null ? '-' : (string)$totalRows ?></b>
            • Page <b><?= (string)$page ?></b> / <b><?= (string)$maxPage ?></b>
          </div>

          <div class="row" style="margin:10px 0">
            <a href="<?=h(url_with(['page'=>1]))?>">⟪ First</a>
            <a href="<?=h(url_with(['page'=>$prev]))?>">‹ Prev</a>
            <a href="<?=h(url_with(['page'=>$next]))?>">Next ›</a>
            <a href="<?=h(url_with(['page'=>$maxPage]))?>">Last ⟫</a>
          </div>

          <div class="scroll">
            <table id="dataTable" data-wrap="0">
              <thead>
                <tr>
                  <?php foreach($columns as $c): ?>
                    <th><?=h($c)?></th>
                  <?php endforeach; ?>
                </tr>
              </thead>
              <tbody>
                <?php if(!$rows): ?>
                  <tr><td colspan="<?=count($columns)?>" class="muted" style="padding:14px">No rows.</td></tr>
                <?php else: ?>
                  <?php foreach($rows as $r): ?>
                    <tr>
                      <?php foreach($columns as $c): ?>
                        <?php
                          $v = $r[$c] ?? null;
                          if ($v === null) $out = 'NULL';
                          elseif (is_bool($v)) $out = $v ? 'true' : 'false';
                          elseif (is_scalar($v)) $out = (string)$v;
                          else $out = json_encode($v);
                        ?>
                        <td title="<?=h($out)?>"><?=h($out)?></td>
                      <?php endforeach; ?>
                    </tr>
                  <?php endforeach; ?>
                <?php endif; ?>
              </tbody>
            </table>
          </div>
        <?php endif; ?>
      </div>

      <div class="card">
        <h2>History</h2>
        <div class="muted">File: <code><?=h($historyFile)?></code></div>
        <?php if(!$historyNewestFirst): ?>
          <div class="muted" style="margin-top:8px">Belum ada riwayat.</div>
        <?php else: ?>
          <div class="scroll" style="max-height:42vh;margin-top:10px">
            <table>
              <thead><tr><th>Created</th><th>DB_NAME</th><th>DB_USER</th><th>DB_PASS</th><th>USER_HOST</th></tr></thead>
              <tbody>
                <?php foreach($historyNewestFirst as $r): ?>
                  <tr>
                    <td><?=h($r['created_at'] ?? '')?></td>
                    <td><code><?=h($r['db_name'] ?? '')?></code></td>
                    <td><code><?=h($r['db_user'] ?? '')?></code></td>
                    <td><code><?=h($r['db_pass'] ?? '')?></code></td>
                    <td><code><?=h($r['user_host'] ?? ($cfg['grant_host'] ?? '%'))?></code></td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        <?php endif; ?>
      </div>

      <div class="card">
        <h2>Hardening minimal</h2>
        <ul class="muted" style="margin:0;padding-left:18px">
          <li>Dashboard ini sensitif: pakai BasicAuth/allowlist IP/VPN.</li>
          <li>Delete hanya boleh untuk DB prefix <code><?=h(browse_prefix($cfg))?></code>.</li>
          <li>Jika <code>grant_host = '%'</code>, jangan buka port 3306 ke publik tanpa firewall/VPN.</li>
        </ul>
      </div>
    </main>
  </div>
</body>
</html>
