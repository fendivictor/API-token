########################################################
# This library contains 2 method of API authentication #
########################################################
# 1. With Signature and Timeout Validation
# 2. With Token and Expiration Time
# 3. Utility to print json and get data from clients

Example:

public function index()
	{
		$auth = $this->auth->check_auth_client('GET');
		$response = [];
		
		$status = isset($auth['status']) ? $auth['status'] : 401;
		$message = isset($auth['message']) ? $auth['message'] : 'Unauthorized';
		
		if ($auth === true) {
			$status = 404;
			$message = 'Data Not Found';

			$params = $this->input->get();
			$data = $this->Lokasi_Model->get_location($params);

			if ($data) {
				$response = $data;

				$status = 200;
				$message = 'OK';
			}
		}

		$this->auth->print_json($status, $message, $response);
	}
