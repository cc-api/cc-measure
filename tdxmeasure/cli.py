"""
Dump command line
"""

from abc import abstractmethod
import logging
import logging.config
import os
import argparse
import random
import base64
# from .actor import VerifyActor, TDEventLogActor
# from .tdreport import TdReport
from cctrusted_base.api import CCTrustedApi
from cctrusted_vm.cvm import ConfidentialVM
from cctrusted_vm.sdk import CCTrustedVmSdk
from cctrusted_base.tdx.rtmr import TdxRTMR
from cctrusted_base.tcg import TcgAlgorithmRegistry
from cctrusted_base.tcgcel import TcgTpmsCelEvent
from cctrusted_base.eventlog import TcgEventLog

# from .ccel import CCEL

LOG = logging.getLogger(__name__)


class TDXMeasurementCmdBase:
    """
    Base class for TDX measurement commands.
    """

    def __init__(self):
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')

    @abstractmethod
    def run(self):
        """
        Interface to be impelemented by child classes
        """
        raise NotImplementedError


class TDXEventLogsCmd(TDXMeasurementCmdBase):
    """
    Cmd executor for dump TDX event logs.
    """

    def run(self):
        """
        Run cmd
        """

        LOG.info("=> Get Event Logs")
        if ConfidentialVM.detect_cc_type() == CCTrustedApi.TYPE_CC_NONE:
            LOG.error("This is not a confidential VM!")
            return
        if os.geteuid() != 0:
            LOG.error("Please run as root which is required for this example!")
            return

        parser = argparse.ArgumentParser(
            description="The example utility to fetch CC event logs")
        parser.add_argument('-s', type=int,
                            help='index of first event log to fetch', dest='start')
        parser.add_argument("-c", type=int, help="number of event logs to fetch",
                            dest="count")
        parser.add_argument("-f", type=bool, help="enable canonical tlv format", default=False,
                            dest="cel_format")
        args = parser.parse_args()

        event_logs = CCTrustedVmSdk.inst().get_cc_eventlog(args.start, args.count)
        if event_logs is None:
            LOG.error("No event log fetched. Check debug log for issues.")
            return
        LOG.info("Total %d of event logs fetched.", len(event_logs))

        res = CCTrustedApi.replay_cc_eventlog(event_logs)
        LOG.info("Replayed result of collected event logs:")
        # pylint: disable-next=C0201
        for key in res.keys():
            LOG.info("RTMR[%d]: ", key)
            LOG.info("     %s", res.get(key).get(12).hex())

        LOG.info("Dump collected event logs:")
        for event in event_logs:
            if isinstance(event, TcgTpmsCelEvent):
                if args.cel_format:
                    TcgTpmsCelEvent.encode(event, TcgEventLog.TCG_FORMAT_CEL_TLV).dump()
                else:
                    event.to_pcclient_format().dump()
            else:
                event.dump()


class TDXVerifyCmd(TDXMeasurementCmdBase):
    """
    Cmd executor for verify RTMR
    """

    def _check_imr(self, imr_index: int, alg_id: int, rtmr: bytes):
        """Check individual IMR.
        Compare the 4 IMR hash with the hash derived by replay event log. They are expected to be same.
        Args:
            imr_index: an integer specified the IMR index.
            alg_id: an integer specified the hash algorithm.
            rtmr: bytes of RTMR data for comparison.
        """
        imr = CCTrustedVmSdk.inst().get_cc_measurement([imr_index, alg_id])
        digest_obj = imr.digest(alg_id)
        digest_hash = digest_obj.hash
        if digest_hash != rtmr:
                LOG.error(f"Replay IMR {imr_index} value does not match real IMR.")
        else:
            LOG.info(f"Verify event log replay value for {imr_index} successfully. RTMR[{imr_index}] value is {rtmr.hex()}.")

    def _get_rtmr_replayed(self):
        """Get RTMRs from event log by replay."""
        rtmr_len = TdxRTMR.RTMR_LENGTH_BY_BYTES
        rtmr_cnt = TdxRTMR.RTMR_COUNT
        rtmrs = [bytearray(rtmr_len)] * rtmr_cnt
        event_logs = CCTrustedVmSdk.inst().get_cc_eventlog()
        rtmrs = CCTrustedApi.replay_cc_eventlog(event_logs)
        return rtmrs

    def run(self):
        """
        Run cmd
        """
        LOG.info("=> Verify RTMR")

        # It needs to compare rtmr returned from cc-trusted-api and rtmr replayed by event logs
        rtmrs_replay = self._get_rtmr_replayed()

        # Verify RTMR
        alg = CCTrustedVmSdk.inst().get_default_algorithms()
        for imr_idx, digests in rtmrs_replay.items():
            self._check_imr(imr_idx, alg.alg_id, digests[alg.alg_id])


class TDXQuoteCmd(TDXMeasurementCmdBase):
    """
    Cmd executor to dump TDQuote.
    """

    OUT_FORMAT_RAW = "raw"
    OUT_FORMAT_HUMAN = "human"

    def _out_format_validator(self, out_format):
        """Validator (callback for ArgumentParser) of output format

        Args:
            out_format: User specified output format.

        Returns:
            Validated value of the argument.

        Raises:
            ValueError: An invalid value is given by user.
        """
        if out_format not in (self.OUT_FORMAT_HUMAN, self.OUT_FORMAT_RAW):
            raise ValueError
        return out_format

    def _make_nounce(self):
        """Make nonce for demo.

        Returns:
            A nonce for demo that is base64 encoded bytes reprensting a 64 bits unsigned integer.
        """
        # Generte a 64 bits unsigned integer randomly (range from 0 to 64 bits max).
        rand_num = random.randrange(0x0, 0xFFFFFFFFFFFFFFFF, 1)
        nonce = base64.b64encode(rand_num.to_bytes(8, "little"))
        return nonce

    def _make_userdata(self):
        """Make userdata for demo.

        Returns:
            User data that is base64 encoded bytes for demo.
        """
        userdata = base64.b64encode(bytes("demo user data", "utf-8"))
        return userdata

    def run(self):
        """Example to call get_cc_report and dump the result to stdout."""
        if ConfidentialVM.detect_cc_type() == CCTrustedApi.TYPE_CC_NONE:
            LOG.error("This is not a confidential VM!")
            return
        if os.geteuid() != 0:
            LOG.error("Please run as root which is required for this example!")
            return

        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-f",
            action="store",
            default=self.OUT_FORMAT_RAW,
            dest="out_format",
            help="Output format: raw/human. Default raw.",
            type=self._out_format_validator
        )
        args = parser.parse_args()

        nonce = self._make_nounce()
        LOG.info("demo random number in base64: %s", nonce.decode("utf-8"))
        userdata = self._make_userdata()
        LOG.info("demo user data in base64: %s", userdata.decode("utf-8"))

        quote = CCTrustedVmSdk.inst().get_cc_report(nonce, userdata)
        if quote is not None:
            quote.dump(args.out_format == self.OUT_FORMAT_RAW)
        else:
            LOG.error("Fail to get Quote!")
            LOG.error("Please double check the log and your config!")


class TDXRTMRCmd(TDXMeasurementCmdBase):
    """
    Cmd executor to get RTMR
    """

    def run(self):
        """
        Run cmd
        """
        LOG.info("=> Get RTMR")
        if ConfidentialVM.detect_cc_type() == CCTrustedApi.TYPE_CC_NONE:
            LOG.error("This is not a confidential VM!")
            return
        if os.geteuid() != 0:
            LOG.error("Please run as root which is required for this example!")
            return

        count = CCTrustedVmSdk.inst().get_measurement_count()
        LOG.info("Measurement Count: %d", count)
        for index in range(CCTrustedVmSdk.inst().get_measurement_count()):
            alg = CCTrustedVmSdk.inst().get_default_algorithms()
            imr = CCTrustedVmSdk.inst().get_cc_measurement([index, alg.alg_id])
            digest_obj = imr.digest(alg.alg_id)

            hash_str = ""
            for hash_item in digest_obj.hash:
                hash_str += "".join([f"{hash_item:02x}", " "])

            LOG.info("Algorithms: %s", str(alg))
            LOG.info("HASH: %s", hash_str)
