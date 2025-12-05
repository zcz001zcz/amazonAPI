<?php

namespace App;

class RedisSession
{
	private $redis;

	public function __construct()
	{
		$this->redisHost = getenv('REDIS_HOST') ?: 'redis';
		$this->redisPort = (int)(getenv('REDIS_PORT') ?: 6379);
		$this->redisPassword = getenv('REDIS_PASSWORD') ?: null;

		$this->redis = new \Redis();
		$this->redis->connect($this->redisHost, $this->redisPort);
	}

	public function start(string $sessionName = 'FBASESSION')
	{
		session_name($sessionName);

		session_set_save_handler(
			[$this, 'open'],
			[$this, 'close'],
			[$this, 'read'],
			[$this, 'write'],
			[$this, 'destroy'],
			[$this, 'gc']
		);

		session_start();
	}

	public function open($savePath, $sessionName) { return true; }
	public function close() { return true; }

	public function read($id)
	{
		$data = $this->redis->get("session:$id");
		return $data ?: '';
	}

	public function write($id, $data)
	{
		$this->sessionLifetime = (int)(getenv('SESSION_LIFETIME') ?: 3600);
		return $this->redis->setex("session:$id", $this->sessionLifetime, $data);
	}

	public function destroy($id)
	{
		$this->redis->del("session:$id");
		return true;
	}

	public function gc($maxLifetime) { return true; }
}