
export class TransportWrapper {
    constructor(original_transport) {
        this._original_transport = original_transport;
    }

    function exchange(apduCommand) {
        return original_transport.exchange(apduCommand);
    }
}
