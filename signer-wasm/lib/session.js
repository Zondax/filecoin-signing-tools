import { DeviceNotSupported, UnknownDevice } from './errors';
import FilecoinApp from "./ledger/index.js"

const DeviceEnum = {
  LEDGER: 'ledger',
  TREZOR: 'trezor'
};


// Utility class to hold hardware device session
class DeviceSession {
  constructor (device) {
    this.device = device;

    switch (device) {
      case DeviceEnum.LEDGER:
        this.session = new FilecoinApp();
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
