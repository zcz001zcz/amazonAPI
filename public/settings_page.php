<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Settings - Amazon FBA Shipping</title>
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
				<a href="/" class="btn btn-outline-light btn-sm ms-2">
					<i class="bi bi-search"></i> Dashboard
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
		<div class="settings-wrapper">
			<div class="settings-card">
				<h2>Amazon API</h2>

				<?php if (!empty($settingsError)): ?>
					<div class="settings-alert settings-alert-error"><?= htmlspecialchars($settingsError) ?></div>
				<?php endif; ?>

				<?php if (!empty($success)): ?>
					<div class="settings-alert settings-alert-success"><?= htmlspecialchars($success) ?></div>
				<?php endif; ?>

				<form method="POST" action="/?page=settings">
					<input type="hidden" name="save_settings" value="1">
					
					<?php if ($isDemoUser): ?>
					<h4>Create User Account</h4>
					<p class="form-help-text">Fill these only if you want to convert this demo account into a real one.</p>

					<div class="mb-3">
						<label class="form-label">New Login</label>
						<input type="text" name="new_login" class="form-control" placeholder="Choose new username">
					</div>

					<div class="mb-3">
						<label class="form-label">New Password</label>
						<input type="password" name="new_password" class="form-control" placeholder="Choose new password">
					</div>
					
					<hr class="my-4">
					<?php endif; ?>

					<div class="mb-3">
						<label for="client_id" class="form-label">Client ID *</label>
						<input type="text"
							   class="form-control"
							   id="client_id"
							   name="client_id"
							   value="<?= htmlspecialchars($userAmazonCreds['client_id'] ?? '') ?>"
							   placeholder="amzn1.application-oa2-client.xxxxxxxxxx">
						<div class="form-help-text">Your Amazon SP-API Application Client ID</div>
					</div>

					<div class="mb-3">
						<label for="client_secret" class="form-label">Client Secret *</label>
						<input type="password"
							   class="form-control"
							   id="client_secret"
							   name="client_secret"
							   value="<?= htmlspecialchars($userAmazonCreds['client_secret'] ?? '') ?>"
							   placeholder="Your client secret">
						<div class="form-help-text">Your Amazon SP-API Application Client Secret</div>
					</div>

					<div class="mb-3">
						<label for="refresh_token" class="form-label">Refresh Token *</label>
						<input type="text"
							   class="form-control"
							   id="refresh_token"
							   name="refresh_token"
							   value="<?= htmlspecialchars($userAmazonCreds['refresh_token'] ?? '') ?>"
							   placeholder="Atzr|xxxxxxxxxx">
						<div class="form-help-text">Your Amazon SP-API Refresh Token (long-lived credential)</div>
					</div>

					<div class="mb-3">
						<label for="region" class="form-label">AWS Region</label>
						<select class="form-select" id="region" name="region">
							<option value="us-east-1" <?= ($userAmazonCreds['region'] ?? '') === 'us-east-1' ? 'selected' : '' ?>>US East (North America)</option>
							<option value="eu-west-1" <?= ($userAmazonCreds['region'] ?? '') === 'eu-west-1' ? 'selected' : '' ?>>EU West (Europe)</option>
							<option value="us-west-2" <?= ($userAmazonCreds['region'] ?? '') === 'us-west-2' ? 'selected' : '' ?>>US West (Far East)</option>
						</select>
						<div class="form-help-text">Select the region for your Amazon marketplace</div>
					</div>

					<div class="mb-3">
						<label for="marketplace_id" class="form-label">Marketplace ID</label>
						<select class="form-select" id="marketplace_id" name="marketplace_id">
							<option value="ATVPDKIKX0DER" <?= ($userAmazonCreds['marketplace_id'] ?? '') === 'ATVPDKIKX0DER' ? 'selected' : '' ?>>United States (US)</option>
							<option value="A2EUQ1WTGCTBG2" <?= ($userAmazonCreds['marketplace_id'] ?? '') === 'A2EUQ1WTGCTBG2' ? 'selected' : '' ?>>Canada (CA)</option>
							<option value="A1AM78C64UM0Y8" <?= ($userAmazonCreds['marketplace_id'] ?? '') === 'A1AM78C64UM0Y8' ? 'selected' : '' ?>>Mexico (MX)</option>
							<option value="A1PA6795UKMFR9" <?= ($userAmazonCreds['marketplace_id'] ?? '') === 'A1PA6795UKMFR9' ? 'selected' : '' ?>>Germany (DE)</option>
							<option value="A1RKKUPIHCS9HS" <?= ($userAmazonCreds['marketplace_id'] ?? '') === 'A1RKKUPIHCS9HS' ? 'selected' : '' ?>>Spain (ES)</option>
							<option value="A13V1IB3VIYZZH" <?= ($userAmazonCreds['marketplace_id'] ?? '') === 'A13V1IB3VIYZZH' ? 'selected' : '' ?>>France (FR)</option>
							<option value="A1F83G8C2ARO7P" <?= ($userAmazonCreds['marketplace_id'] ?? '') === 'A1F83G8C2ARO7P' ? 'selected' : '' ?>>United Kingdom (UK)</option>
							<option value="APJ6JRA9NG5V4" <?= ($userAmazonCreds['marketplace_id'] ?? '') === 'APJ6JRA9NG5V4' ? 'selected' : '' ?>>Italy (IT)</option>
						</select>
						<div class="form-help-text">Select your Amazon marketplace</div>
					</div>

					<div class="mb-3">
						<label for="shipping_speed" class="form-label">Default Shipping Speed</label>
						<select class="form-select" id="shipping_speed" name="shipping_speed">
							<option value="Standard"  <?= ($userAmazonCreds['shipping_speed'] ?? '') === 'Standard' ? 'selected' : '' ?>>Standard (3–5 days)</option>
							<option value="Expedited" <?= ($userAmazonCreds['shipping_speed'] ?? '') === 'Expedited' ? 'selected' : '' ?>>Expedited (2–3 days)</option>
							<option value="Priority"  <?= ($userAmazonCreds['shipping_speed'] ?? '') === 'Priority' ? 'selected' : '' ?>>Priority (1–2 days)</option>
						</select>
						<div class="form-help-text">Default shipping method for FBA orders</div>
					</div>

					<div class="button-group mt-4">
						<button type="submit" class="btn btn-amazon">Save Settings</button>
					</div>
				</form>

				<hr class="my-4">

				<?php if (!$isDemoUser): ?>
				<form method="POST" action="/" onsubmit="return confirm('Are you sure you want to delete this account and return to demo mode?');">
					<button type="submit" name="clear_settings" class="btn btn-danger">Delete Account</button>
				</form>
				<?php endif; ?>

			</div>
		</div>
	</div>
	<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>