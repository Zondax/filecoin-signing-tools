import { DeviceNotSupported, UnknownDevice } from './errors';
import FilecoinApp from "@zondax/ledger-filecoin"
import TransportNodeHid from "@ledgerhq/hw-transport-node-hid";

const DeviceEnum = {
  LEDGER: 'ledger',
  TREZOR: 'trezor'
};


// Utility class to hold hardware device session
class DeviceSession {
  constructor (device) {
    this.device = device;
    this.session = null
  }

  async connect () {
    switch (this.device) {
      case DeviceEnum.LEDGER:
        const transport = await TransportNodeHid.create();
        this.session = new FilecoinApp(transport);
        break;
      case DeviceEnum.TREZOR:
        throw new DeviceNotSupported();
      default:
        throw new UnknownDevice();
    }
  }

}

export default DeviceSession;
export { DeviceEnum };
