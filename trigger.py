import requests
from typing import List, Dict, Any
from emla.models import DiscoveredEndpoint, ErrorResponse

class ErrorTriggerModule:
    """Executes controlled, non-destructive error-triggering requests against discovered endpoints."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.headers = {"User-Agent": "EMLA-Security-Analyzer/1.0"}

    def execute_request(
        self,
        url: str,
        method: str = "GET",
        params: Dict[str, Any] = None,
        data: Dict[str, Any] = None,
        headers: Dict[str, str] = None
    ) -> ErrorResponse:
        """Sends HTTP request and wraps output safely into an ErrorResponse object."""
        req_headers = {**self.headers, **(headers or {})}
        try:
            resp = requests.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=req_headers,
                timeout=self.timeout
            )
            return ErrorResponse(
                url=resp.url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                method=method.upper(),
                params=params or data
            )
        except requests.RequestException as e:
            return ErrorResponse(
                url=url,
                status_code=500,
                headers={},
                body=f"Connection failure: {str(e)}",
                method=method.upper(),
                params=params or data
            )

    def generate_triggers(self, endpoint: DiscoveredEndpoint) -> List[ErrorResponse]:
        """Generates a suite of controlled error-provocation requests for a given endpoint."""
        responses: List[ErrorResponse] = []

        # 1. Trigger: Type Mismatch (e.g. string 'abc' for numeric parameters)
        if endpoint.params:
            mismatch_params = {p: "EMLA_INVALID_TYPE_STRING_'\"" for p in endpoint.params}
            if endpoint.method == "GET":
                responses.append(self.execute_request(endpoint.url, method="GET", params=mismatch_params))
            else:
                responses.append(self.execute_request(endpoint.url, method=endpoint.method, data=mismatch_params))

        # 2. Trigger: Missing Parameters (omitting required fields)
        if endpoint.params:
            empty_params = {}
            if endpoint.method == "GET":
                responses.append(self.execute_request(endpoint.url, method="GET", params=empty_params))
            else:
                responses.append(self.execute_request(endpoint.url, method=endpoint.method, data=empty_params))

        # 3. Trigger: Special Characters Injection (boundary quotes & SQL syntax triggers)
        if endpoint.params:
            special_params = {p: "' OR 1=1 --" for p in endpoint.params}
            if endpoint.method == "GET":
                responses.append(self.execute_request(endpoint.url, method="GET", params=special_params))
            else:
                responses.append(self.execute_request(endpoint.url, method=endpoint.method, data=special_params))

        # 4. Trigger: Unexpected HTTP Method / Verb Mismatch
        inv_method = "POST" if endpoint.method == "GET" else "GET"
        responses.append(self.execute_request(endpoint.url, method=inv_method))

        # 5. Trigger: Malformed Header / Accept Header Mismatch
        responses.append(self.execute_request(
            endpoint.url,
            method=endpoint.method,
            headers={"Accept": "application/invalid-mime-type"}
        ))

        return responses
