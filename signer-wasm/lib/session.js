import { DeviceNotSupported, UnknownDevice } from './errors';
import FilecoinApp from "./ledger/index.js"

const DeviceEnum = {
  LEDGER: 'ledger',
  TREZOR: 'trezor'
};


// Utility class to hold hardware device session
class DeviceSession {

  device = null
  session = null

  constructor (device) {
    this.device = device;

    if (device === DeviceEnum.LEDGER) {
    }

    if (device === )

    switch (device) {
      case DeviceEnum.LEDGER:
        this.session = new FilecoinApp();
        break;
      case DeviceEnum.TREZOR:
        throw new DeviceNotSupported();
      default:
        throw
    }

  }
}

export default DeviceSession;
export { DeviceEnum };
