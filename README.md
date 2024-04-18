## CC Measurement Tool

The measurement tool runs within Confidential VM (CVM), such as TDX guest, to get measurement, event logs and replay event logs. 

It supports Intel® TDX to get RTMR, event logs, Quote and verify RTMR. Find more details of RTMT and Quote in
[Intel® TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html).

The tool is implemented based on APIs from [cc-trusted-api](https://github.com/cc-api/cc-trusted-api) and SDK from [cc-trusted-vmsdk](https://github.com/cc-api/cc-trusted-vmsdk).

## Getting Started

It provides 4 commands as follows.

- [tdx_eventlogs](./tdx_eventlogs): Get TD event logs, including both launch time and runtime event logs.
- [tdx_rtmr](./tdx_rtmr): Get TD RTMRs.
- [tdx_tdquote](./tdx_tdquote): Get TD Quote for remote attestation.
- [tdx_verify_rtmr](./tdx_verify_rtmr):  Replay event logs and verify the hash with RTMR values.

_NOTE: The tool should be installed and run in a TDX guest with root permission._

### Installation

Build and install CC Measurement Tool in a TDX guest.

```sh
$ cd cc-measure
$ sudo su
$ virtualenv venv && source venv/bin/activate
$ python3 setup.py bdist_wheel
$ pip3 install dist/*.whl --force-reinstall
```

### Run the commands
1. Get Event Logs.

    ```
    $ ./tdx_eventlogs

    # Display event log in Canoical Event Logs (CEL) format.
    $ ./tdx_eventlogs -f true

    # Display event logs from index 100.
    $ ./tdx_eventlogs -s 100

    # Display 20 event logs from index 100
    ./tdx_eventlogs -s 100 -c 20
    ```

    The example output for the event log is [example event logs output with IMA](https://github.com/cc-api/cc-trusted-api/blob/main/docs/vmsdk-eventlog-sample-output-with-IMA.txt).

2. Get TD Quote.

    _NOTE: Make sure you have remote attestation environment setup on the host to get quote._

    ```
    $ ./tdx_tdquote

    # Display quote in human friendly format.
    $ ./tdx_tdquote -f human
    ```

2. Get RTMR.

    ```
    ./tdx_rtmr
    ```

3. Verify the event logs.

    ```
    ./tdx_verify_rtmr
    ```
