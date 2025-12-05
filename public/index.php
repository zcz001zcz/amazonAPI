<?php

require __DIR__ . '/../vendor/autoload.php';

use App\RedisSession;
use App\Services\FbaService;
use App\Data\AbstractOrder;
use App\Data\BuyerInterface;
use App\Data\UserSettings;

$session = new RedisSession();
$session->start();

$redis = new Redis();

$redisHost = getenv('REDIS_HOST') ?: 'redis';
$redisPort = (int)(getenv('REDIS_PORT') ?: 6379);
$redisPassword = getenv('REDIS_PASSWORD') ?: null;
$demoUsername = getenv('DEMO_USERNAME') ?: 'admin';
$demoPassword = getenv('DEMO_PASSWORD') ?: 'admin123';

$redis->connect(getenv('REDIS_HOST') ?: $redisHost, intval(getenv('REDIS_PORT') ?: $redisPort));
if (($pwd = getenv('REDIS_PASSWORD')) !== false && $pwd !== '') {
	$redis->auth($pwd);
}
$userSettings = new UserSettings($redis);

function isDemoCredentials(string $login, string $password): bool {
	global $demoUsername, $demoPassword;
	$validUsername = $demoUsername;
	$validPassword = $demoPassword;
	return ($login === $validUsername && $password === $validPassword);
}

$orderInfo = null;
$buyerInfo = null;
$trackingNumber = null;
$error = null;
$success = null;
$settingsSaved = false;
$settingsError = null;
$loginError = null;

$loggedIn = $_SESSION['logged_in'] ?? false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout'])) {
	session_destroy();
	header('Location: /');
	exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['clear_settings'])) {
	$username = $_SESSION['username'] ?? null;
	if ($username) {
		$userSettings->deleteUser($username);
	}
	unset($_SESSION['demo_user']);
	session_destroy();
	header('Location: /');
	exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'], $_POST['password']) && !$loggedIn) {
	$login = trim($_POST['login']);
	$password = $_POST['password'];

	if (isDemoCredentials($login, $password)) {
		if (!isset($_SESSION['demo_user'])) {
			$uniqueUser = "demo_" . bin2hex(random_bytes(5));
			$_SESSION['demo_user'] = $uniqueUser;
			$userSettings->createDemoUser($uniqueUser);
		}
		$_SESSION['logged_in'] = true;
		$_SESSION['username'] = $_SESSION['demo_user'];
		$_SESSION['login_time'] = time();

		header('Location: /');
		exit;
	}
	else {
		if ($userSettings->checkPassword($login, $password)) {
			$_SESSION['logged_in'] = true;
			$_SESSION['username'] = $login;
			$_SESSION['login_time'] = time();
			header('Location: /');
			exit;
		}
		else {
			$loginError = 'Invalid username or password';
		}
	}
}

$loggedIn = $_SESSION['logged_in'] ?? false;
if (!$loggedIn) {
	?>
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width,initial-scale=1">
		<title>Login - Amazon FBA Shipping</title>
		<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
		<link href="/assets/main.css" rel="stylesheet">
	</head>
	<body>
	<div class="login-wrapper">
		<div class="login-card">
			<h1 class="card-title">Amazon FBA Shipping</h1>
			<p class="subtitle">Sign in to manage your orders</p>

			<?php if ($loginError): ?>
				<div class="alert alert-danger" role="alert"><?= htmlspecialchars($loginError) ?></div>
			<?php endif; ?>

			<form method="POST">
				<div class="mb-3">
					<label for="login" class="form-label">Username</label>
					<input type="text" id="login" name="login" class="form-control" required autofocus value="<?= htmlspecialchars($_POST['login'] ?? '') ?>">
				</div>

				<div class="mb-3">
					<label for="password" class="form-label">Password</label>
					<input type="password" id="password" name="password" class="form-control" required>
				</div>

				<button type="submit" class="btn btn-amazon w-100">Sign In</button>
			</form>

			<div class="demo-info mt-3">
				<strong>Demo:</strong><br>
				Username: <code><?=$demoUsername?></code><br>
				Password: <code><?=$demoPassword?></code>
			</div>
		</div>
	</div>

	</body>
	</html>
	<?php
	exit;
}

$username = $_SESSION['username'] ?? 'User';
$userAmazonCreds = $userSettings->getAmazonCredentials($username);
$hasAmazonSetup = $userSettings->hasAmazonCredentials($username);

$isDemoUser = false;
$profile = $userSettings->getProfile($username);
if (!empty($profile['is_demo']) && intval($profile['is_demo']) === 1) {
	$isDemoUser = true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_settings'])) {
	$username = $_SESSION['username'] ?? '';

	$credentials = [
		'client_id' => trim($_POST['client_id'] ?? ''),
		'client_secret' => trim($_POST['client_secret'] ?? ''),
		'refresh_token' => trim($_POST['refresh_token'] ?? ''),
		'region' => trim($_POST['region'] ?? 'us-east-1'),
		'marketplace_id' => trim($_POST['marketplace_id'] ?? 'ATVPDKIKX0DER'),
		'shipping_speed' => trim($_POST['shipping_speed'] ?? 'Standard'),
	];

	$newLogin = trim($_POST['new_login'] ?? '');
	$newPassword = trim($_POST['new_password'] ?? '');

	if (!empty($credentials['client_id']) && !preg_match('/^amzn1\.application-oa2-client\.[A-Za-z0-9]+$/', $credentials['client_id'])) {
		$settingsError = 'Invalid Client ID format. It must start with "amzn1.application-oa2-client." followed by alphanumeric characters.';
	}

	if (!empty($credentials['refresh_token']) && !preg_match('/^Atz[ra]\|/', $credentials['refresh_token'])) {
		$settingsError = 'Invalid Refresh Token format. It must start with "Atzr|" or "Atza|".';
	}

	$hasClientId = !empty($credentials['client_id']);
	$hasClientSecret = !empty($credentials['client_secret']);
	$hasRefreshToken = !empty($credentials['refresh_token']);
	
	if (($hasClientId || $hasClientSecret || $hasRefreshToken) && !($hasClientId && $hasClientSecret && $hasRefreshToken)) {
		$settingsError = 'Incomplete credentials. Please provide all three: Client ID, Client Secret, and Refresh Token, or leave all empty for demo mode.';
	}

	if (empty($settingsError)) {
		if (!empty($newLogin) && !empty($newPassword)) {

			if ($userSettings->userExists($newLogin)) {
				$settingsError = "Username already taken. The username '{$newLogin}' is already in use. Please choose a different username.";
			}
			else {
				try {

					$userSettings->createUser($newLogin, $newPassword);
					$userSettings->saveAmazonCredentials($newLogin, $credentials);

					if (strpos($username, 'demo_') === 0) {
						$userSettings->deleteUser($username);
					}

					$_SESSION['username'] = $newLogin;
					$_SESSION['logged_in'] = true;

					$settingsSaved = true;
					$success = "Account created successfully! You are now logged in as '{$newLogin}'.";
					if (!empty($credentials['client_id'])) {
						$success .= "Amazon credentials saved.";
					}

					$username = $newLogin;
					$userAmazonCreds = $userSettings->getAmazonCredentials($username);
					$isDemoUser = false;
					$hasAmazonSetup = $userSettings->hasAmazonCredentials($username);
				} catch (Exception $e) {
					$errorMsg = $e->getMessage();
					if (strpos($errorMsg, 'User already exists') !== false) {
						$settingsError = "Username already taken. The username '{$newLogin}' is already registered. Please choose a different username.";
					}
					else {
						$settingsError = "Failed to create user: " . strip_tags($errorMsg);
					}
				}
			}
		}
		else {

			if ($userSettings->saveAmazonCredentials($username, $credentials)) {
				$settingsSaved = true;
				$hasCredentials = !empty($credentials['client_id']) && !empty($credentials['client_secret']) && !empty($credentials['refresh_token']);
				if ($hasCredentials) {
					$success = "Amazon credentials saved successfully! You can now ship orders in LIVE mode.";
				}
				else {
					$success = "Settings saved. You are in DEMO mode (empty credentials).";
				}
				$userAmazonCreds = $userSettings->getAmazonCredentials($username);
				$hasAmazonSetup = $userSettings->hasAmazonCredentials($username);
			}
			else {
				$settingsError = "Failed to save settings for '{$username}'. Please try again.";
			}
		}
	}
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {

	if ($_POST['action'] === 'search' && isset($_POST['order_id'])) {
		$orderId = (int)$_POST['order_id'];

		try {

			$orderFile = __DIR__ . '/../mock/order.' . $orderId . '.json';
			if (!file_exists($orderFile)) {
				throw new RuntimeException("Order #{$orderId} not found in local database");
			}

			$orderData = json_decode(file_get_contents($orderFile), true);
			if (!$orderData) {
				throw new RuntimeException("Failed to parse order data");
			}

			$orderInfo = $orderData;

			$clientId = $orderData['client_id'] ?? 0;
			if ($clientId) {
				$buyerFile = __DIR__ . '/../mock/buyer.' . $clientId . '.json';
				if (file_exists($buyerFile)) {
					$buyerInfo = json_decode(file_get_contents($buyerFile), true);
				}
			}
		} catch (Exception $e) {
			$errorMessage = $e->getMessage();

			if (strpos($errorMessage, 'not found in local database') !== false) {
				$error = "Order Not Found";
				$settingsError = "Order #{$orderId} doesn't exist in the database. Please check the order ID and try again.";
			} elseif (strpos($errorMessage, 'Failed to parse order data') !== false) {
				$error = "Data Error";
				$settingsError = "Order data is corrupted or invalid. Please contact support.";
			}
			else {
				$error = "Search Failed";
				$settingsError = strip_tags($errorMessage);
			}
		}
	}

	if ($_POST['action'] === 'ship' && isset($_POST['order_id'])) {
		$orderId = (int)$_POST['order_id'];

		try {

			$orderFile = __DIR__ . '/../mock/order.' . $orderId . '.json';
			if (!file_exists($orderFile)) {
				throw new RuntimeException("Order #{$orderId} not found");
			}

			$orderData = json_decode(file_get_contents($orderFile), true);
			$clientId = $orderData['client_id'] ?? 0;

			$buyerData = ['email' => 'buyer@test.com', 'phone' => ''];
			if ($clientId) {
				$buyerFile = __DIR__ . '/../mock/buyer.' . $clientId . '.json';
				if (file_exists($buyerFile)) {
					$buyerData = json_decode(file_get_contents($buyerFile), true);
				}
			}

			$order = new class($orderId, $orderData) extends AbstractOrder {
				private $mockData;
				public function __construct(int $id, array $data) {
					parent::__construct($id);
					$this->mockData = $data;
				}
				protected function loadOrderData(int $id): array {
					return $this->mockData;
				}
			};
			$order->load();

			$buyer = new class($buyerData) implements BuyerInterface {
				private $data;
				public function __construct(array $data) { $this->data = $data; }
				public function offsetExists($offset): bool { return isset($this->data[$offset]); }
				public function offsetGet($offset) { return $this->data[$offset] ?? null; }
				public function offsetSet($offset, $value): void { $this->data[$offset] = $value; }
				public function offsetUnset($offset): void { unset($this->data[$offset]); }
			};

			$fbaService = new FbaService($userAmazonCreds);
			$trackingNumber = $fbaService->ship($order, $buyer);

			$mode = $hasAmazonSetup ? 'LIVE' : 'DEMO';
			$success = "Order shipped successfully in {$mode} mode!";

			$orderInfo = $orderData;
			$buyerInfo = $buyerData;
		} catch (Exception $e) {
			$errorMessage = $e->getMessage();

			if (strpos($errorMessage, 'Failed to refresh access token') !== false) {
				if (strpos($errorMessage, 'invalid_client') !== false) {
					$error = "Amazon API Error: Invalid credentials";
					$settingsError = "Your Client ID or Client Secret is incorrect. Please check your Amazon SP-API credentials in Settings.";
				} elseif (strpos($errorMessage, 'invalid_grant') !== false) {
					$error = "Amazon API Error: Invalid or expired refresh token";
					$settingsError = "Your Refresh Token has expired or is invalid. Please generate a new one in Amazon Seller Central.";
				}
				else {
					$error = "Amazon API Error: Authentication failed";
					$settingsError = "Could not authenticate with Amazon. Please verify your credentials in Settings.";
				}
			} elseif (strpos($errorMessage, 'Amazon API Error') !== false) {

				if (preg_match('/HTTP (\d+)/', $errorMessage, $matches)) {
					$httpCode = $matches[1];
					switch ($httpCode) {
						case '400':
							$error = "Bad Request";
							$settingsError = "The order data is invalid or incomplete. Please check shipping address and product SKUs.";
							break;
						case '403':
							$error = "Access Denied";
							$settingsError = "Your Amazon account doesn't have permission to use FBA Outbound API. Request access in Seller Central.";
							break;
						case '404':
							$error = "API Endpoint Not Found";
							$settingsError = "Amazon API endpoint error. Please verify your Region settings.";
							break;
						case '429':
							$error = "Rate Limit Exceeded";
							$settingsError = "Too many requests to Amazon API. Please wait a few minutes and try again.";
							break;
						case '500':
						case '503':
							$error = "Amazon Server Error";
							$settingsError = "Amazon's servers are experiencing issues. Please try again later.";
							break;
						default:
							$error = "Amazon API Error (HTTP {$httpCode})";
							$settingsError = strip_tags($errorMessage);
					}
				}
				else {
					$error = "Amazon API Error";
					$settingsError = strip_tags($errorMessage);
				}
			} elseif (strpos($errorMessage, 'Failed to connect to Amazon') !== false) {
				$error = "Connection Error";
				$settingsError = "Could not connect to Amazon SP-API. Please check your internet connection.";
			} elseif (strpos($errorMessage, 'Product missing SKU') !== false) {
				$error = "Invalid Product Data";
				$settingsError = strip_tags($errorMessage);
			} elseif (strpos($errorMessage, 'Missing required shipping field') !== false) {
				$error = "Incomplete Shipping Address";
				$settingsError = strip_tags($errorMessage);
			}
			else {
				$error = "Shipping Failed";
				$settingsError = strip_tags($errorMessage);
			}

			try {
				$orderFile = __DIR__ . '/../mock/order.' . $orderId . '.json';
				if (file_exists($orderFile)) {
					$orderInfo = json_decode(file_get_contents($orderFile), true);
					$clientId = $orderInfo['client_id'] ?? 0;
					if ($clientId) {
						$buyerFile = __DIR__ . '/../mock/buyer.' . $clientId . '.json';
						if (file_exists($buyerFile)) {
							$buyerInfo = json_decode(file_get_contents($buyerFile), true);
						}
					}
				}
			} catch (Exception $e2) {
				// ignore
			}
		}
	}
}

// settings page
if (isset($_GET['page']) && $_GET['page'] === 'settings') {
	include __DIR__ . '/settings_page.php';
	exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<title>Dashboard - Amazon FBA Shipping</title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
	<link href="/assets/main.css" rel="stylesheet">
</head>
<body>
	<nav class="navbar navbar-expand-lg navbar-dark navbar-custom">
		<div class="container">
			<a class="navbar-brand" href="/">
				Amazon FBA Shipping
				<?php if ($hasAmazonSetup): ?>
					<span class="status-badge status-live">LIVE MODE</span>
				<?php else: ?>
					<span class="status-badge status-demo">DEMO MODE</span>
				<?php endif; ?>
			</a>
			<div class="d-flex align-items-center">
				<span class="navbar-text">
					<i class="bi bi-person-circle"></i> Welcome, <?= htmlspecialchars($username) ?>
				</span>
				<a href="?page=settings" class="btn btn-outline-light btn-sm ms-2">
					<i class="bi bi-gear-fill"></i> Settings
				</a>
				<form method="POST" class="d-inline ms-2">
					<button type="submit" name="logout" class="btn btn-outline-light btn-sm">
						<i class="bi bi-box-arrow-right"></i> Logout
					</button>
				</form>
			</div>
		</div>
	</nav>

	<div class="container main-container">
		<?php if ($error): ?>
			<div class="alert alert-danger alert-dismissible fade show" role="alert">
				<i class="bi bi-exclamation-triangle-fill"></i>
				<strong><?= htmlspecialchars($error) ?></strong>
				<?php if (!empty($settingsError)): ?>
					<br><small><?= htmlspecialchars($settingsError) ?></small>
					<?php if (strpos($settingsError, 'Settings') !== false || strpos($settingsError, 'credentials') !== false): ?>
						<br><a href="?page=settings" class="alert-link">Go to Settings →</a>
					<?php endif; ?>
				<?php endif; ?>
				<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
			</div>
		<?php endif; ?>

		<?php if ($success): ?>
			<div class="alert alert-success alert-dismissible fade show" role="alert">
				<i class="bi bi-check-circle-fill"></i>
				<strong><?= htmlspecialchars($success) ?></strong>
				<?php if ($trackingNumber): ?>
					<br><small>Tracking number generated: <code><?= htmlspecialchars($trackingNumber) ?></code></small>
				<?php endif; ?>
				<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
			</div>
		<?php endif; ?>

		<div class="card dashboard-card">
			<div class="card-header-custom">
				<h2><i class="bi bi-search"></i> Search Order</h2>
			</div>
			<div class="card-body">
				<?php if (!$hasAmazonSetup): ?>
					<div class="alert alert-warning-custom" role="alert">
						<i class="bi bi-exclamation-circle-fill"></i>
						<strong>Demo Mode Active</strong><br>
						You haven't configured Amazon API credentials yet. Orders will generate demo tracking numbers.<br>
						<a href="?page=settings">Click here to configure your Amazon credentials</a>
					</div>
				<?php endif; ?>

				<form method="POST" class="search-form">
					<input type="hidden" name="action" value="search">
					<input 
						type="number" 
						name="order_id" 
						class="form-control" 
						placeholder="Enter Order ID (e.g., 16400)" 
						required 
						value="<?= htmlspecialchars($_POST['order_id'] ?? '') ?>"
					>
					<button type="submit" class="btn btn-amazon ms-2">
						<i class="bi bi-search"></i> Search
					</button>
				</form>
			</div>
		</div>

		<?php if ($orderInfo): ?>
			<div class="card dashboard-card">
				<div class="card-header-custom">
					<h2><i class="bi bi-box-seam"></i> Order #<?= htmlspecialchars($orderInfo['order_id']) ?></h2>
				</div>
				<div class="card-body">
					<div class="row g-3">
						<div class="col-md-4">
							<div class="info-section">
								<h3><i class="bi bi-info-circle"></i> Order Information</h3>
								<div class="info-item">
									<span class="info-label">Order Date:</span>
									<?= htmlspecialchars($orderInfo['order_date'] ?? 'N/A') ?>
								</div>
								<div class="info-item">
									<span class="info-label">Status:</span>
									<span class="badge bg-primary"><?= htmlspecialchars($orderInfo['status'] ?? 'N/A') ?></span>
								</div>
								<div class="info-item">
									<span class="info-label">Total:</span>
									<strong class="text-success">$<?= htmlspecialchars(number_format($orderInfo['final_price'] ?? 0, 2)) ?></strong>
								</div>
								<?php if (!empty($orderInfo['comments'])): ?>
									<div class="info-item">
										<span class="info-label">Comments:</span><br>
										<small class="text-muted"><?= htmlspecialchars($orderInfo['comments']) ?></small>
									</div>
								<?php endif; ?>
							</div>
						</div>

						<div class="col-md-4">
							<div class="info-section">
								<h3><i class="bi bi-geo-alt"></i> Shipping Address</h3>
								<address class="mb-0">
									<strong><?= htmlspecialchars($orderInfo['buyer_name'] ?? 'N/A') ?></strong><br>
									<?= htmlspecialchars($orderInfo['shipping_street'] ?? '') ?><br>
									<?= htmlspecialchars($orderInfo['shipping_city']) ?>, 
									<?= htmlspecialchars($orderInfo['shipping_state']) ?> 
									<?= htmlspecialchars($orderInfo['shipping_zip']) ?><br>
									<?= htmlspecialchars($orderInfo['shipping_country']) ?>
								</address>
							</div>
						</div>

						<?php if ($buyerInfo): ?>
							<div class="col-md-4">
								<div class="info-section">
									<h3><i class="bi bi-person"></i> Buyer Information</h3>
									<div class="info-item">
										<span class="info-label">Username:</span>
										<?= htmlspecialchars($buyerInfo['shop_username'] ?? 'N/A') ?>
									</div>
									<div class="info-item">
										<span class="info-label">Email:</span>
										<a href="mailto:<?= htmlspecialchars($buyerInfo['email'] ?? '') ?>" class="text-decoration-none">
											<?= htmlspecialchars($buyerInfo['email'] ?? 'N/A') ?>
										</a>
									</div>
									<div class="info-item">
										<span class="info-label">Phone:</span>
										<?= htmlspecialchars($buyerInfo['phone'] ?? 'N/A') ?>
									</div>
								</div>
							</div>
						<?php endif; ?>
					</div>

					<?php if (!empty($orderInfo['products'])): ?>
						<h3 class="mt-4 mb-3"><i class="bi bi-cart"></i> Products (<?= count($orderInfo['products']) ?>)</h3>
						<div class="table-responsive">
							<table class="table table-hover products-table">
								<thead>
									<tr>
										<th>SKU</th>
										<th>Product Name</th>
										<th>Qty</th>
										<th>Price</th>
										<th>Comments</th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ($orderInfo['products'] as $product): ?>
										<tr>
											<td><code><?= htmlspecialchars($product['sku'] ?? 'N/A') ?></code></td>
											<td><?= htmlspecialchars($product['title'] ?? 'N/A') ?></td>
											<td><span class="badge bg-secondary"><?= htmlspecialchars($product['ammount'] ?? 1) ?></span></td>
											<td class="text-success fw-bold">$<?= htmlspecialchars(number_format($product['buying_price'] ?? 0, 2)) ?></td>
											<td><small class="text-muted"><?= htmlspecialchars($product['comment'] ?? '-') ?></small></td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						</div>
					<?php endif; ?>

					<?php if ($trackingNumber): ?>
						<div class="tracking-box">
							<h3><i class="bi bi-check-circle-fill"></i> Order Shipped Successfully!</h3>
							<p class="mb-3">Tracking Number:</p>
							<div class="tracking-number"><?= htmlspecialchars($trackingNumber) ?></div>
							<p class="mt-3 mb-0">
								<small class="text-muted">
									<i class="bi bi-info-circle"></i> 
									<?php if ($hasAmazonSetup): ?>
										Your order has been submitted to Amazon's fulfillment network.
									<?php else: ?>
										This is a demo tracking number. Configure Amazon credentials in Settings to ship real orders.
									<?php endif; ?>
								</small>
							</p>
						</div>
					<?php else: ?>
						<div class="text-center mt-4">
							<form method="POST">
								<input type="hidden" name="action" value="ship">
								<input type="hidden" name="order_id" value="<?= htmlspecialchars($orderInfo['order_id'] ?? '') ?>">
								<button type="submit" class="btn btn-success btn-lg">
									Ship with Amazon FBA
								</button>
							</form>
						</div>
					<?php endif; ?>
				</div>
			</div>
		<?php endif; ?>
	</div>
	<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>