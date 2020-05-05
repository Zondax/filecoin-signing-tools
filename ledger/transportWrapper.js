
export class TransportWrapper {
    function exchange(apduCommand) {
        return original_transport.exchange(apduCommand);
    }
}
