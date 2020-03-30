// When we try to call a function and that device is not `soft`
class OperationNotAllow extends Error {
  constructor (message) {
    super(message);
    this.name = "OperationNotAllow";
  }
}

// Device not supported yet
class DeviceNotSupported extends Error {
  constructor () {
    super();
    this.message = "Device not yet supported";
    this.name = "DeviceNotSupported";
  }
}

class UnknownDevice extends Error {
  contructor () {
    super();
    this.message = "Unknown device please refer to documentation for a list if supported devices.";
    this.name = "UnknownDevice";
  }
}

class NotASession extends Error {
  contructor () {
    super();
    this.message = "Please pass a DeviceSession instance in order to communicate with the device.";
    this.name = "NotASession";
  }
}

export { OperationNotAllow, DeviceNotSupported, UnknownDevice, NotASession };
