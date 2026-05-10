<?php

require 'vendor/autoload.php';

use GuzzleHttp\Client;

$client = new Client();

$response = $client->request('GET', 'https://api.github.com');

echo "Status: " . $response->getStatusCode();
