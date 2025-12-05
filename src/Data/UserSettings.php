<?php
namespace App\Data;

class UserSettings
{
	private $redis;

	public function __construct(\Redis $redis)
	{
		$this->redis = $redis;
	}

	private function profileKey(string $username): string
	{
		return "user:{$username}:profile";
	}

	private function amazonKey(string $username): string
	{
		return "user:{$username}:amazon";
	}

	public function userExists(string $username): bool
	{
		return $this->redis->exists($this->profileKey($username)) === 1;
	}

	public function createDemoUser(string $username): bool
	{
		$key = $this->profileKey($username);
		$now = time();
		$data = [
			'password_hash' => '',
			'created_at' => $now,
			'is_demo' => 1
		];
		$this->redis->hMSet($key, $data);
		$this->redis->hMSet($this->amazonKey($username), [
			'client_id' => '',
			'client_secret' => '',
			'refresh_token' => '',
			'region' => 'us-east-1',
			'marketplace_id' => 'ATVPDKIKX0DER',
			'shipping_speed' => 'Standard'
		]);
		return true;
	}

	public function createUser(string $username, string $password): bool
	{
		if ($this->userExists($username)) {
			throw new \RuntimeException("User already exists");
		}
		$hash = password_hash($password, PASSWORD_DEFAULT);
		$now = time();
		$this->redis->hMSet($this->profileKey($username), [
			'password_hash' => $hash,
			'created_at' => $now,
			'is_demo' => 0
		]);
		$this->redis->hMSet($this->amazonKey($username), [
			'client_id' => '',
			'client_secret' => '',
			'refresh_token' => '',
			'region' => 'us-east-1',
			'marketplace_id' => 'ATVPDKIKX0DER',
			'shipping_speed' => 'Standard'
		]);
		return true;
	}

	public function checkPassword(string $username, string $password): bool
	{
		if (!$this->userExists($username)) return false;
		$hash = $this->redis->hGet($this->profileKey($username), 'password_hash');
		if (!$hash) return false;
		return password_verify($password, $hash);
	}
	
	public function getProfile(string $username): array
	{
		return $this->redis->hGetAll($this->profileKey($username)) ?: [];
	}

	public function saveAmazonCredentials(string $username, array $creds): bool
	{
		if (!$this->userExists($username)) {
			$this->createDemoUser($username);
		}
		$allowed = [
			'client_id' => $creds['client_id'] ?? '',
			'client_secret' => $creds['client_secret'] ?? '',
			'refresh_token' => $creds['refresh_token'] ?? '',
			'region' => $creds['region'] ?? 'us-east-1',
			'marketplace_id' => $creds['marketplace_id'] ?? 'ATVPDKIKX0DER',
			'shipping_speed' => $creds['shipping_speed'] ?? 'Standard'
		];
		$this->redis->hMSet($this->amazonKey($username), $allowed);
		return true;
	}

	public function getAmazonCredentials(string $username): array
	{
		if (!$this->userExists($username)) return [];
		$data = $this->redis->hGetAll($this->amazonKey($username));
		return $data ?: [];
	}

	public function hasAmazonCredentials(string $username): bool
	{
		$data = $this->getAmazonCredentials($username);
		return !empty($data['client_id']);
	}

	public function deleteUser(string $username): bool
	{
		$this->redis->del([$this->profileKey($username), $this->amazonKey($username)]);
		return true;
	}

	public function migrateDemoToReal(string $demoUser, string $newLogin, string $newPassword): bool
	{
		if (strpos($demoUser, 'demo_') !== 0) {
			throw new \RuntimeException("Source user is not demo");
		}
		if ($this->userExists($newLogin)) {
			throw new \RuntimeException("Target login already exists");
		}

		$this->createUser($newLogin, $newPassword);

		$creds = $this->getAmazonCredentials($demoUser);
		if ($creds) {
			$this->saveAmazonCredentials($newLogin, $creds);
		}

		$this->deleteUser($demoUser);
		return true;
	}
}