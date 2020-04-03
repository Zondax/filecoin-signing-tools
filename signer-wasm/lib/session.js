import { DeviceNotSupported, UnknownDevice } from './errors';
import FilecoinApp from './ledger/'

const DeviceEnum = {
  LEDGER: 'ledger',
  TREZOR: 'trezor'
};


// Utility class to hold hardware device session
class DeviceSession {
  constructor (device, transport) {
    this.device = device;

    switch (this.device) {
      case DeviceEnum.LEDGER:
        this.app = new FilecoinApp(transport);
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
