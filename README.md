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
$ source setupenv.sh
```

### Run the commands
1. Get Event Logs.

    ```
    $ sudo ./tdx_eventlogs

    # Display event log in Canoical Event Logs (CEL) format.
    $ sudo ./tdx_eventlogs -f true

    # Display event logs from index 10.
    $ sudo ./tdx_eventlogs -s 10

    # Display 10 event logs from index 10.
    $ sudo ./tdx_eventlogs -s 10 -c 10
    ```

    The example output for the event log is [example event logs output with IMA](https://github.com/cc-api/cc-trusted-api/blob/main/docs/vmsdk-eventlog-sample-output-with-IMA.txt).

2. Get TD Quote.

    _NOTE: Make sure you have remote attestation environment setup on the host to get quote._

    ```
    $ sudo ./tdx_tdquote

    # Display quote in human friendly format.
    $ sudo ./tdx_tdquote -f human
    ```

3. Get RTMR.

    ```
    $ sudo ./tdx_rtmr
    ```

4. Verify the event logs.

    ```
    $ sudo ./tdx_verify_rtmr
    ```

5. (Optional) Exit python virtual environment after running the commands.

    ```
    $ deactivate
    ```
