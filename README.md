![Static Badge](https://img.shields.io/badge/-RDP%20BANNER%20COLLECTOR-brightgreen?style=plastic&logo=go&logoColor=white&logoSize=auto&labelColor=abcdea&color=FF4571&cacheSeconds=3600)
## RDP Scanner
_A banner collector that collects NTLM-info and login screen from RDP servers. Original repo: https://github.com/tomatome/grdp_

<p align="center">
  <img src="https://github.com/user-attachments/assets/75e74111-eb7c-4698-a198-e84f5ae3096c" alt="Scanner example" width="1000"/>
  <br/>
  <em>The result of the RDP server scan</em>
</p>

## Install

```go
go install github.com/trueHyper/rdp-scanner/cmd/rdp-scanner@latest
```
## Usage
```go
rdp-scanner -host 217.77.56.189:3389 -w 1080 -h 640 -c 40 -t 3000
```
| Flag    | Description |
| --------| ----------- |
| `-host` | **(Required)** Target IP and port in the format `<ip>:<port>`. |
| `-w`    | Screen width in pixels. |
| `-h`    | Screen height in pixels. |
| `-t`    | Bitmap update interval in milliseconds — how much time the bitmaps have to update between frames. |
| `-c`    | Compression percentage (0–100) — defines how much the screen image will be compressed. |

## Example
```go
 rdp-scanner -host 217.77.56.189:3389 -w 100 -h 50 -c 100 -t 2500
```
This will connect to 217.77.56.189 on port 3389, request a screen resolution of 100×50 pixels, apply 100% compression, and set a 2.5-second bitmap update interval.

## Output
```bash
true_hyper@HOME-PC:~$ rdp-scanner -host 217.77.56.189:3389 -w 100 -h 50 -c 100 -t 2500
{
    "ntlm_info": {
        "netbios_computer_name": [
            "WST-KRC-004"
        ],
        "product_version": [
            "10.0.19041"
        ],
        "system_time": [
            "2025-04-29T00:46:25Z"
        ],
        "target_name": [
            "WST-KRC-004"
        ],
        "netbios_domain_name": [
            "WST-KRC-004"
        ],
        "dns_computer_name": [
            "WST-KRC-004"
        ],
        "dns_domain_name": [
            "WST-KRC-004"
        ],
        "dns_tree_name": [
            ""
        ]
    },
    "host": "217.77.56.189:3389",
    "screenshot": "/9j/2wCEAP////////////////////////////////////////////////////////////////////////////////////8B///////////////////////////////////////////////////////////////////////////////////////AABEIADIAZAMBIgACEQEDEQH/xAGiAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+gEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoLEQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/AI6KKKACiiigAooooAKWkpaACiiigAooooAKKKKAEopaKAEopaKACiiigAooooAKKKKACiiigAooooAKKKKACjFFLTEJRRRSGFFFFABRRRQAUUUUAFFFFABRRRQAUtJS00JiUUUUhhRRRQAUUUUALRRRQAUUUUAf/9k="
}
````
