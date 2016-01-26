<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Requests;
use App\Http\Controllers\Controller;
use App\Libs\OAuth\OAuthConsumer;
use App\Libs\OAuth\OAuthException;
use App\Libs\OAuth\OAuthRequest;
use App\Libs\OAuth\OAuthSignatureMethod_HMAC_SHA1;
use Torann\GeoIP\GeoIPFacade as GeoIP;

class ReputationController extends Controller
{
    /**
     * Detects whether it's file or text
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function detectRequestType(Request $request)
    {
        if ($request->hasFile('file')) {
            $result = $this->fileScan($request);
        } elseif ($request->get('categorize')) {
            $domain = $request->get('categorize');
            $result = $this->categorize($domain);
        } else {
            $text = $request->get('text');
            $result = $this->detectTextRequestType($text);
        }
        return response()->json(compact('result'));
    }

    /**
     * Detects whether it's url, ip, domain or hash.
     *
     * @param $data
     * @internal param UrlScanRequest $request
     * @return array|bool|float|int|string
     */
    private function detectTextRequestType($data)
    {
        $requestParts = explode('.', $data);
        if (!isset($requestParts[1])) {
            return $this->hashScan($data);
        } elseif (strpos($data, "://")) {
            return $this->urlScan($data);
        } elseif (count($requestParts) == 4) {
            return $this->ipScan($data);
        } else {
            return $this->domainScan($data);
        }
    }
    /*---------------------- File And Hash Scan ----------------------*/
    /**
     * Scans file for viruses.
     *
     * @param $data
     * @internal param FileScanRequest $request
     * @return array|bool|float|int|string
     */
    private function fileScan($data)
    {
        $file = $data->file('file');
//$file_to_scan = $file->getRealPath();
//$file_size_mb = filesize($file_to_scan) / 1024 / 1024;
        $scan = new \VirusTotal\File(getenv('VIRUSTOTAL_API_KEY'));
        $resp = $scan->scan($file->getRealPath());
//$resp = $scan->rescan($file->getRealPath());
        if (isset($resp['resource'])) {
            $resp['Resource']['result'] = $scan->getReport($resp['resource']);
        }
        return $resp;
    }

    /**
     * Scans hash for viruses.
     *
     * @param $data
     * @return mixed
     */
    private function hashScan($data)
    {
        $post_url = 'https://www.virustotal.com/vtapi/v2/file/rescan';
        $post['apikey'] = getenv('VIRUSTOTAL_API_KEY');
        $post['resource'] = $data;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $post_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $api_reply = curl_exec($ch);
        curl_close($ch);
        $api_reply_array = json_decode($api_reply, true);
        return $api_reply_array;
    }
    /*---------------------- URL, IP And Domain Scan ----------------------*/
    /**
     * Scans url for viruses.
     *
     * @param $data
     * @return array|bool|float|int|string
     */
    private function urlScan($data)
    {
        $url_scan = new \VirusTotal\Url(getenv('VIRUSTOTAL_API_KEY'));
        $url_resp = $url_scan->getReport($data);
        return $url_resp;
    }

    /**
     * Scans ip for viruses and Location info.
     *
     * @param $data
     * @return array|bool|float|int|string
     */
    private function ipScan($data)
    {
        $ip_scan = new \VirusTotal\Ip(getenv('VIRUSTOTAL_API_KEY'));
        $ip_resp = $ip_scan->getReport($data);
        $location = GeoIP::getLocation('232.223.11.11');
        if (isset($location)) {
            $ip_resp['location'] = $location;
        }
        return $ip_resp;
    }

    /**
     * Scans domain for viruses.
     *
     * @param $data
     * @return array|bool|float|int|string
     */
    private function domainScan($data)
    {
        $domain_scan = new \VirusTotal\Domain(getenv('VIRUSTOTAL_API_KEY'));
        $domain_resp = $domain_scan->getReport($data);
        return $domain_resp;
    }
    /*---------------------- Categorization ----------------------*/
    /**
     * Brightcloud categorization, returns URI list, info and categories.
     *
     * @param $domain
     * @return \Illuminate\Http\JsonResponse
     * @internal param Request $request
     * @internal param $domain
     * @internal param Request $request
     */
    public function categorize($domain)
    {
        $uriList = $this->uriList($domain);
        $categoryList = $this->categoryList($domain);
        $uriInfo = $this->uriInfo($domain);
        return ['URI list' => $uriList, 'URI info' => $uriInfo, 'Category list' => $categoryList];
    }

    /**
     * Get URI info.
     *
     * @param $domain
     * @return mixed|string
     * @internal param string $type
     */
    private function uriInfo($domain)
    {
        $consumer_key = env('BRIGHTCLOUD_CONSUMER_KEY');
        $consumer_secret = env('BRIGHTCLOUD_CONSUMER_SECRET');
        $http_method = "GET";
        $rest_endpoint = "http://thor.brightcloud.com:80/rest";
        $uri_info_path = 'uris';
        $uri = $domain;
        $endpoint = "$rest_endpoint/$uri_info_path/" . urlencode($uri);
        $oauth_header = $this->getOAuthHeader($consumer_key, $consumer_secret, $http_method, $endpoint);
        return $this->sendCURL($endpoint, $oauth_header);
    }

    /**
     * Get URI list.
     *
     * @param $domain
     * @return mixed|string
     */
    private function uriList($domain)
    {
        $consumer_key = env('BRIGHTCLOUD_CONSUMER_KEY');
        $consumer_secret = env('BRIGHTCLOUD_CONSUMER_SECRET');
        $http_method = "GET";
        $rest_endpoint = "http://thor.brightcloud.com:80/rest";
        $uri_info_path = 'uris';
        $uri = $domain;
        $endpoint = "$rest_endpoint/$uri_info_path/";
        $oauth_header = $this->getOAuthHeader($consumer_key, $consumer_secret, $http_method, $endpoint);
        return $this->sendCURL($endpoint, $oauth_header);
    }

    /**
     * Get URI Category list.
     *
     * @param $domain
     * @return mixed|string
     */
    private function categoryList($domain)
    {
        $consumer_key = env('BRIGHTCLOUD_CONSUMER_KEY');
        $consumer_secret = env('BRIGHTCLOUD_CONSUMER_SECRET');
        $http_method = "GET";
        $rest_endpoint = "http://thor.brightcloud.com:80/rest";
        $uri_info_path = 'uris';
        $uri = $domain;
        $endpoint = "$rest_endpoint/$uri_info_path/" . 'categories';
        $oauth_header = $this->getOAuthHeader($consumer_key, $consumer_secret, $http_method, $endpoint);
        return $this->sendCURL($endpoint, $oauth_header);
    }

    /**
     * Get OAuth header for cURL request.
     *
     * @param $consumer_key
     * @param $consumer_secret
     * @param $http_method
     * @param $endpoint
     * @return string
     * @throws OAuthException
     */
    private function getOAuthHeader($consumer_key, $consumer_secret, $http_method, $endpoint)
    {
// Establish an OAuth Consumer based on read credentials
        $consumer = new OAuthConsumer($consumer_key, $consumer_secret, NULL);
// Setup OAuth request - Use NULL for OAuthToken parameter
        $request = OAuthRequest::from_consumer_and_token($consumer, NULL, $http_method, $endpoint, NULL);
// Sign the constructed OAuth request using HMAC-SHA1 - Use NULL for OAuthToken parameter
        $request->sign_request(new OAuthSignatureMethod_HMAC_SHA1(), $consumer, NULL);
// Extract OAuth header from OAuth request object and keep it handy in a variable
        $oauth_header = $request->to_header();
        return $oauth_header;
    }

    /**
     * Send cURL request to Brightcloud.
     *
     * @param $endpoint
     * @param $oauth_header
     * @return mixed|string
     */
    private function sendCURL($endpoint, $oauth_header)
    {
// Initialize a cURL session
        $curl = curl_init($endpoint);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_FAILONERROR, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
// Include OAuth Header as part of HTTP headers in the cURL request
        curl_setopt($curl, CURLOPT_HTTPHEADER, array($oauth_header));
// Make OAuth-signed request to the BCWS server and get hold of server response
        $response = curl_exec($curl);
        if (!$response) {
            $response = curl_error($curl);
        }
// Close cURL session
        curl_close($curl);
// Process server response
        return $response;
    }
}
