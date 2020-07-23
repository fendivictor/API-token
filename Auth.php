<?php  
defined('BASEPATH') or exit('No direct script access allowed');

class Auth
{
    // set your header here.
    private $client_service = 'manjo-1235679#*!'; // change to yours
    private $auth_key = 'manjo'; // change to yours

    ########################################################
    # This library contains 2 method of API authentication #
    ########################################################
    # 1. With Signature and Timeout Validation
    # 2. With Token and Expiration Time
    # 3. Utility to print json and get data from clients

    # 1. authentication model dynamic signature and timeout validation
    function check_auth_client($method = 'GET', $flag = true)
    {
        $request_method = $_SERVER['REQUEST_METHOD'];
        if ($method == $request_method) {
            $ci =& get_instance();
            $client_service = $ci->input->get_request_header('Client-Service', true);
            $auth_key = $ci->input->get_request_header('Auth-Key', true);
            $user_id = $ci->input->get_request_header('User-Id', true); // user id untuk akses
            $timestamp = $ci->input->get_request_header('Timestamp', true); // random timestamp.
            // using milliseconds in java 
            $signature = $ci->input->get_request_header('Signature', true); // signature

            $header = [$client_service, $auth_key, $user_id, $timestamp, $signature];

            // at development server set true
            if ($_SERVER['SERVER_NAME'] == 'localhost' || $_SERVER['SERVER_NAME'] == 'manjo.my.id') {
                return true;
            }

            if ($auth_key == $this->auth_key && $client_service == $this->client_service) {
                if ($flag == true) {
                    // create encoded signature
                    $encoded_signature = $this->generate_signature($user_id, $timestamp);
                    // jika cocok maka true
                    // cocokkan encoded signature dgn signature dari request
                    if ($signature == $encoded_signature) {
                        // convert miliseconds to normal miliseconds
                        $time = round($timestamp / 1000, 0);

                        $check_expired = $this->check_expired($time); // check expiration time of token
                        if ($check_expired) {
                            return true;
                        } else {
                            return [
                                'status' => 401,
                                'message' => 'Token has been expired or revoked'
                            ];
                        }
                    } else {
                        return [
                            'status' => 401,
                            'message' => 'Unauthorized'
                        ];
                    }
                } else {
                    return true;
                }
            } else {
                return [
                    'status' => 401,
                    'message' => 'Unauthorized'
                ];
            }
        } else {
            return [
                'status' => 400,
                'message' => 'Bad Request'
            ];
        }
    }

    # 2. authentication model static token and expiration
    function auth_token($method = 'GET', $flag = true)
    {
        $ci =& get_instance();
        $request_method = $_SERVER['REQUEST_METHOD'];
        $userid = $ci->input->get_request_header('Userid', true);
        $token = $ci->input->get_request_header('Token', true);
        $client_service = $ci->input->get_request_header('Client-Service', true);
        $auth_key = $ci->input->get_request_header('Auth-Key', true);

        if ($method == $request_method) {
            if ($auth_key == $this->auth_key && $client_service == $this->client_service) {
                if ($flag == true) {

                    //  cek is token masih valid
                    $q = $ci->db->query("
                        SELECT a.*
                        FROM tb_authentication a
                        INNER JOIN tb_user b ON a.users_id = b.username
                        WHERE a.users_id = '$userid'
                        AND a.token = '$token'
                        AND a.expired_at > NOW() ")->row();

                    if (!empty($q)) {
                        // update token
                        $expired_at = date("Y-m-d H:i:s", strtotime('+24 hours'));
                        $update_at = date('Y-m-d H:i:s');

                        $data = array(
                            'expired_at' => $expired_at,
                            'updated_at' => $update_at
                        );

                        $ci->db->where('token', $token)
                            ->where('users_id', $userid)
                            ->update('tb_authentication', $data);

                        return true;
                    } else {
                        // token sudah expired
                        return $this->print_json(401, 'Unauthorized, Expired Authentication', []);
                    }
                } else {
                    return true;
                }
            } else {
                return $this->print_json(401, 'Unauthorized', []);
            }
        } else {
            return $this->print_json(400, 'Bad Request', []);
        }
    }

    # 2. create token 
    function create_token($username)
    {
        $token = crypt(substr(md5(date("Y m d H i s u")), 0, 7), '');
        $expired_at = date("Y-m-d H:i:s", strtotime('+24 hours'));

        $ci->db->where(['users_id' => $username])->delete('tb_authentication');

        // create tokennya
        $dt_token = [
            'users_id' => $username,
            'token' => $token,
            'expired_at' => $expired_at
        ];

        $ci->db->insert('tb_authentication', $dt_token);

        if ($ci->db->affected_rows() > 0) {
            return $dt_token;
        } else {
            return false;
        }
    }

    # 1. 
    function generate_timestamp()
    {
        date_default_timezone_set('Asia/Jakarta');

        $timestamp = time();

        return $timestamp;
    }

    # 1.
    function generate_signature($user_id = '', $timestamp = '')
    {
        $signature = hash_hmac('sha256', $user_id.'&'.$timestamp, $user_id.'die', true);

        return base64_encode($signature);
    }

    # 1. 
    function check_expired($time = 0)
    {
        date_default_timezone_set('Asia/Jakarta');

        $start = date('Y-m-d H:i:s', strtotime('-1 minutes'));
        $limit = date('Y-m-d H:i:s', strtotime('+1 minutes'));
        $time = date('Y-m-d H:i:s', $time);

        if ($time > $start && $time < $limit) {
            return true;
        }

        return false;
    }

    # 3. 
    function get_params()
    {
        return json_decode(file_get_contents('php://input'), true);
    }

    # 3.
    function print_json($status = 200, $message = '', $data = [])
    {
        $ci =& get_instance();
        $response = [
            'response' => $data,
            'metadata' => [
                'status' => $status,
                'message' => $message
            ]
        ];

        $class = $ci->router->fetch_class();
        $method = $ci->router->fetch_method();
        $header = getallheaders();
        $auth_key = $ci->input->get_request_header('Auth-Key', true);

        if ($_SERVER['REQUEST_METHOD'] == 'GET') {
            $request = $ci->input->get();
        } else if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $request = $this->get_params();
        } else if ($_SERVER['REQUEST_METHOD'] == 'DELETE') {
            $request = $ci->input->get();
        } else if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
            $request = $this->get_params();
        } else {
            $request = '';
        }

        $data = [
            'api' => $class.'/'.$method,
            'request' => json_encode($request),
            'response' => json_encode($response),
            'header' => json_encode($header),
            'user' => $auth_key
        ];

        $ci->db->insert('log_trx_api', $data);

        $ci->output->set_content_type('application/json');
        $ci->output->set_status_header(200);
        $ci->output->set_output(json_encode($response));
    }
}
?>