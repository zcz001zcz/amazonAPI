<?php

namespace App\Services;

use App\ShippingServiceInterface;
use App\Data\AbstractOrder;
use App\Data\BuyerInterface;
use RuntimeException;
use DateTime;

/**
 * Amazon FBA Shipping Service
 * 
 * Implements integration with Amazon Fulfillment By Amazon (FBA) network
 * to process and ship orders using Amazon SP-API
 */
class FbaService implements ShippingServiceInterface
{
	private ?array $userCredentials = null;
	private ?string $accessToken = null;
	private ?int $tokenExpiry = null;
	
	private const LWA_ENDPOINT = 'https://api.amazon.com/auth/o2/token';
	private const SP_API_ENDPOINT = 'https://sellingpartnerapi-na.amazon.com';
	private const API_VERSION = '2020-07-01';

	public function __construct(?array $userCredentials = null)
	{
		$this->userCredentials = $userCredentials;
	}

	private function getClientId(): string
	{
		return $this->userCredentials['client_id'] ?? getenv('AMAZON_CLIENT_ID') ?: '';
	}

	private function getClientSecret(): string
	{
		return $this->userCredentials['client_secret'] ?? getenv('AMAZON_CLIENT_SECRET') ?: '';
	}

	private function getRefreshToken(): string
	{
		return $this->userCredentials['refresh_token'] ?? getenv('AMAZON_REFRESH_TOKEN') ?: '';
	}

	private function getRegion(): string
	{
		return $this->userCredentials['region'] ?? getenv('AMAZON_REGION') ?: 'us-east-1';
	}

	private function getMarketplaceId(): string
	{
		return $this->userCredentials['marketplace_id'] ?? getenv('AMAZON_MARKETPLACE_ID') ?: 'ATVPDKIKX0DER';
	}

	private function getShippingSpeed(): string
	{
		return $this->userCredentials['shipping_speed'] ?? getenv('AMAZON_SHIPPING_SPEED') ?: 'Standard';
	}

	public function ship(AbstractOrder $order, BuyerInterface $buyer): string
	{
		try {
			if (!$order->data) {
				$order->load();
			}

			$this->validateOrderData($order);
			$this->validateBuyerData($buyer);

			$clientId = $this->getClientId();
			$clientSecret = $this->getClientSecret();
			$refreshToken = $this->getRefreshToken();
			
			if (empty($clientId) || empty($clientSecret) || empty($refreshToken)) {
				return $this->generateDemoTracking($order);
			}

			$fulfillmentOrderId = $this->generateFulfillmentOrderId($order);
			$destinationAddress = $this->buildDestinationAddress($order, $buyer);
			$items = $this->buildOrderItems($order);
			$orderComment = $this->buildOrderComment($order);

			$accessToken = $this->getAccessToken();

			$response = $this->createFulfillmentOrder(
				$fulfillmentOrderId,
				$order->getOrderId(),
				$orderComment,
				$destinationAddress,
				$items,
				$accessToken
			);

			$trackingNumber = $this->extractTrackingNumber($response, $fulfillmentOrderId);

			$this->logShipment($order->getOrderId(), $trackingNumber);

			return $trackingNumber;

		} catch (RuntimeException $e) {
			$this->logError($order->getOrderId(), $e->getMessage());
			throw $e;
		} catch (\Exception $e) {
			$this->logError($order->getOrderId(), $e->getMessage());
			throw new RuntimeException('Failed to ship order: ' . $e->getMessage(), 0, $e);
		}
	}

	private function validateOrderData(AbstractOrder $order): void
	{
		if (!is_array($order->data)) {
			throw new RuntimeException('Order data is not loaded');
		}

		$products = $order->data['products'] ?? [];
		if (empty($products)) {
			throw new RuntimeException('Order has no products to ship');
		}

		$requiredFields = ['shipping_city', 'shipping_state', 'shipping_country', 'shipping_zip'];
		foreach ($requiredFields as $field) {
			if (empty($order->data[$field])) {
				throw new RuntimeException("Missing required shipping field: {$field}");
			}
		}
	}

	private function validateBuyerData(BuyerInterface $buyer): void
	{
		$email = $buyer['email'] ?? '';
		if (empty($email)) {
			throw new RuntimeException('Buyer email is required');
		}
	}

	private function generateDemoTracking(AbstractOrder $order): string
	{
		$orderId = $order->getOrderId();
		$timestamp = time();
		$random = strtoupper(substr(md5($orderId . $timestamp), 0, 6));
		
		$trackingNumber = "FBA-DEMO-{$orderId}-{$random}";
		
		$this->logShipment($orderId, $trackingNumber, true);
		
		return $trackingNumber;
	}

	private function generateFulfillmentOrderId(AbstractOrder $order): string
	{
		$orderId = $order->getOrderId();
		$timestamp = time();
		return "FBA-{$orderId}-{$timestamp}";
	}

	private function buildDestinationAddress(AbstractOrder $order, BuyerInterface $buyer): array
	{
		$addressText = $order->data['shipping_adress'] ?? '';
		$addressLines = $this->parseAddressLines($addressText);

		$name = $order->data['buyer_name'] ?? $buyer['shop_username'] ?? 'Customer';

		$phone = $buyer['phone'] ?? '';

		return [
			'name' => $name,
			'addressLine1' => $addressLines[0] ?? $order->data['shipping_street'] ?? '',
			'addressLine2' => $addressLines[1] ?? null,
			'city' => $order->data['shipping_city'] ?? '',
			'stateOrRegion' => $order->data['shipping_state'] ?? '',
			'postalCode' => $order->data['shipping_zip'] ?? '',
			'countryCode' => $order->data['shipping_country'] ?? '',
			'phoneNumber' => $phone ?: null,
		];
	}

	private function parseAddressLines(string $address): array
	{
		$lines = array_filter(array_map('trim', explode("\n", $address)));
		$result = [];
		
		foreach ($lines as $line) {
			if (preg_match('/^[A-Za-z]+\s+[A-Za-z]+$/', $line)) {
				continue;
			}
			if (in_array($line, ['United States', 'USA', 'Canada', 'Mexico'])) {
				continue;
			}
			if (preg_match('/^[A-Z]{2}\s+\d{5}/', $line)) {
				continue;
			}
			
			$result[] = $line;
		}
		
		return array_values($result);
	}

	private function buildOrderItems(AbstractOrder $order): array
	{
		$items = [];
		$products = $order->data['products'] ?? [];

		foreach ($products as $product) {
			$sku = $product['sku'] ?? $product['product_code'] ?? '';
			if (empty($sku)) {
				throw new RuntimeException('Product missing SKU: ' . ($product['title'] ?? 'Unknown product'));
			}

			$items[] = [
				'sellerSku' => $sku,
				'sellerFulfillmentOrderItemId' => (string)($product['order_product_id'] ?? uniqid('item_')),
				'quantity' => (int)($product['ammount'] ?? 1),
				'displayableComment' => $product['comment'] ?? null,
			];
		}

		return $items;
	}

	private function buildOrderComment(AbstractOrder $order): string
	{
		$comments = [];

		if (!empty($order->data['comments'])) {
			$comments[] = $order->data['comments'];
		}

		foreach ($order->data['products'] ?? [] as $product) {
			if (!empty($product['comment'])) {
				$title = $product['title'] ?? 'Product';
				$comments[] = substr($title, 0, 30) . ': ' . $product['comment'];
			}
		}

		return implode(' | ', $comments) ?: 'Order from online store';
	}

	private function getAccessToken(): string
	{
		if ($this->accessToken && $this->tokenExpiry && time() < $this->tokenExpiry) {
			return $this->accessToken;
		}

		$this->refreshAccessToken();
		return $this->accessToken;
	}

	private function refreshAccessToken(): void
	{
		$postData = [
			'grant_type' => 'refresh_token',
			'refresh_token' => $this->getRefreshToken(),
			'client_id' => $this->getClientId(),
			'client_secret' => $this->getClientSecret(),
		];

		$ch = curl_init(self::LWA_ENDPOINT);
		curl_setopt_array($ch, [
			CURLOPT_POST => true,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
			CURLOPT_POSTFIELDS => http_build_query($postData),
			CURLOPT_TIMEOUT => 30,
		]);

		$response = curl_exec($ch);
		$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$error = curl_error($ch);
		curl_close($ch);

		if ($error) {
			throw new RuntimeException("Failed to connect to Amazon LWA: {$error}");
		}

		if ($httpCode !== 200) {
			throw new RuntimeException("Failed to refresh access token. HTTP {$httpCode}: {$response}");
		}

		$data = json_decode($response, true);
		if (!isset($data['access_token'])) {
			throw new RuntimeException('Invalid token response from Amazon');
		}
		
		$this->sessionLifetime = (int)(getenv('SESSION_LIFETIME') ?: 3600);

		$this->accessToken = $data['access_token'];
		$this->tokenExpiry = time() + ($data['expires_in'] ?? $this->sessionLifetime) - 60; // 60 sec buffer
	}

	private function createFulfillmentOrder(
		string $fulfillmentOrderId,
		int $displayableOrderId,
		string $orderComment,
		array $destinationAddress,
		array $items,
		string $accessToken
	): array {
		$url = self::SP_API_ENDPOINT . '/fba/outbound/' . self::API_VERSION . '/fulfillmentOrders';
		
		$requestBody = [
			'sellerFulfillmentOrderId' => $fulfillmentOrderId,
			'marketplaceId' => $this->getMarketplaceId(),
			'displayableOrderId' => (string)$displayableOrderId,
			'displayableOrderDateTime' => (new DateTime())->format(DateTime::ISO8601),
			'displayableOrderComment' => $orderComment,
			'shippingSpeedCategory' => $this->getShippingSpeed(),
			'destinationAddress' => $destinationAddress,
			'fulfillmentAction' => 'Ship',
			'items' => $items,
		];

		$jsonBody = json_encode($requestBody);

		$headers = [
			'Content-Type: application/json',
			'x-amz-access-token: ' . $accessToken,
			'User-Agent: FBA-Shipping-Service/1.0 (Language=PHP)',
		];

		$ch = curl_init($url);
		curl_setopt_array($ch, [
			CURLOPT_POST => true,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER => $headers,
			CURLOPT_POSTFIELDS => $jsonBody,
			CURLOPT_TIMEOUT => 30,
		]);

		$response = curl_exec($ch);
		$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$error = curl_error($ch);
		curl_close($ch);

		if ($error) {
			throw new RuntimeException("Failed to connect to Amazon SP-API: {$error}");
		}

		$responseData = json_decode($response, true) ?? [];

		if ($httpCode >= 400) {
			$errorMessage = 'Unknown error';
			if (isset($responseData['errors'][0]['message'])) {
				$errorMessage = $responseData['errors'][0]['message'];
			}
			throw new RuntimeException("Amazon API Error (HTTP {$httpCode}): {$errorMessage}");
		}

		return $responseData;
	}

	private function extractTrackingNumber(array $response, string $fulfillmentOrderId): string
	{
		if (isset($response['errors']) && !empty($response['errors'])) {
			$error = $response['errors'][0];
			throw new RuntimeException('FBA API Error: ' . ($error['message'] ?? 'Unknown error'));
		}

		return $fulfillmentOrderId;
	}

	private function logShipment(int $orderId, string $trackingNumber, bool $isDemo = false): void
	{
		$mode = $isDemo ? '[DEMO MODE]' : '[LIVE MODE]';
		$timestamp = date('Y-m-d H:i:s');
		$message = "{$timestamp} {$mode} Order #{$orderId} shipped. Tracking: {$trackingNumber}\n";
		
		$this->writeLog($message);
	}

	private function logError(int $orderId, string $error): void
	{
		$timestamp = date('Y-m-d H:i:s');
		$message = "{$timestamp} [ERROR] Order #{$orderId} failed: {$error}\n";
		
		$this->writeLog($message);
	}

	private function writeLog(string $message): void
	{
		$logDir = __DIR__ . '/../../logs';
		$logFile = $logDir . '/shipments.log';

		if (!is_dir($logDir)) {
			@mkdir($logDir, 0755, true);
		}

		@file_put_contents($logFile, $message, FILE_APPEND);

		if (getenv('APP_DEBUG') === 'true') {
			error_log($message);
		}
	}

	public function getOrderStatus(string $fulfillmentOrderId): array
	{
		try {
			$accessToken = $this->getAccessToken();
			$url = self::SP_API_ENDPOINT . '/fba/outbound/' . self::API_VERSION . '/fulfillmentOrders/' . $fulfillmentOrderId;
			
			$headers = [
				'Content-Type: application/json',
				'x-amz-access-token: ' . $accessToken,
			];

			$ch = curl_init($url);
			curl_setopt_array($ch, [
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HTTPHEADER => $headers,
				CURLOPT_TIMEOUT => 30,
			]);

			$response = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			curl_close($ch);

			if ($httpCode !== 200) {
				throw new RuntimeException("Failed to get order status. HTTP {$httpCode}");
			}

			return json_decode($response, true) ?? [];

		} catch (\Exception $e) {
			throw new RuntimeException('Failed to get order status: ' . $e->getMessage(), 0, $e);
		}
	}
}