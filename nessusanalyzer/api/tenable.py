import requests
from typing import Dict, Any
from ..utils.logger import logger

class TenableClient:
    def __init__(self, access_key: str, secret_key: str, base_url: str = "https://cloud.tenable.com"):
        self.access_key = access_key
        self.secret_key = secret_key
        self.base_url = base_url
        self.headers = {
            "Accept": "application/json",
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"
        }

    def list_scans(self) -> Dict[str, Any]:
        """Lists available scans from Tenable.io."""
        url = f"{self.base_url}/scans"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error fetching scans from Tenable: {e}")
            raise

    def download_scan(self, scan_id: int, format: str = "nessus") -> bytes:
        """Downloads a specific scan in the given format."""
        # Note: Tenable export is an asynchronous process (export request -> check status -> download)
        # This is a simplified version of what it would look like.
        logger.info(f"Initiating export for scan ID: {scan_id}")
        export_url = f"{self.base_url}/scans/{scan_id}/export"
        
        try:
            # Step 1: Request export
            payload = {"format": format}
            res = requests.post(export_url, headers=self.headers, json=payload)
            res.raise_for_status()
            file_id = res.json().get("file")

            # Step 2: In a real implementation, we would poll for status here.
            # Step 3: Download
            # download_url = f"{self.base_url}/scans/{scan_id}/export/{file_id}/download"
            # res = requests.get(download_url, headers=self.headers)
            # return res.content
            
            logger.warning("Dynamic polling not implemented in this skeleton. Returning file ID.")
            return str(file_id).encode()
        except Exception as e:
            logger.error(f"Error downloading scan: {e}")
            raise
