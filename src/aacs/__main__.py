from . import AACS, KeyNotFound

NUMBER_OF_DEVICES: int = 8
OPTIONS: tuple[str] = {'1', '2', 'q'}


def print_menu():
    """
    Function to print the menu options.
    """
    print('='*19)
    print('Options:')
    print('  1 - Encrypt file.')
    print('  2 - Decrypt file.')
    print('  q - Quit.')
    print()


def ask_revoked_devices() -> set[int]:
    """
    Function to interactively ask the user for revoked devices.

    Returns:
        set[int]: Set containing revoked devices.
    """
    # Get list of revoked devices from 1 to NUMBER_OF_DEVICES
    revoked_devices: set[int] = set()
    print('Introduce devices to revoke them or left or leave empty to finish.')
    print(f'Range: [1, {NUMBER_OF_DEVICES}]')
    while True:
        device: str = input('Device id: ')
        if device == '':
            return revoked_devices
        elif not device.isdigit():
            print('Invalid value!')
        else:
            device: int = int(device)
            if device not in range(1, NUMBER_OF_DEVICES+1):
                print('Value out of range!')
            else:
                revoked_devices.add(device)


def ask_decrypting_device() -> int:
    """
    Function to interactively ask the user for a device to decrypt.

    Returns:
        int: Device id for decryption.
    """
    print('Which device will try to decrypt?')
    print(f'Range: [1, {NUMBER_OF_DEVICES}]')
    while True:
        device: str = input('Device id: ')
        if not device.isdigit():
            print('Invalid value!')
        else:
            device: int = int(device)
            if device not in range(1, NUMBER_OF_DEVICES+1):
                print('Value out of range!')
            else:
                return device


def device_id_to_node_id(tree_levels: int, device_id: int):
    """
    Function to convert device id to binary tree node id.

    Parameters:
        tree_levels (int): Number of tree levels, excluding root.
        device_id (int): Device id.

    Returns:
        int: Node id in the binary tree.
    """
    return device_id + 2**tree_levels - 1


def main():
    """
    Main function to run the AACS application.
    """

    aacs: AACS = AACS(NUMBER_OF_DEVICES)

    print_menu()
    while True:

        # Get option
        option: str = input('Introduce option: ').casefold()
        if option not in OPTIONS:
            continue

        # Quit
        if option == 'q':
            print('Exiting...')
            exit(0)

        if option in {'1', '2'}:

            # Get filenames to encrypt/decrypt
            input_filename: str = input('Introduce input file name: ')
            if input_filename == '':
                print()
                print_menu()
                continue

            output_filename: str = input('Introduce output file name: ')
            if output_filename == '':
                print()
                print_menu()
                continue

            # Convert device id to binary tree node id and revoke
            for id in ask_revoked_devices():
                aacs.revoke(device_id_to_node_id(aacs.t, id))

            # Read input file
            try:
                with open(input_filename, 'rb') as f:
                    data: bytes = f.read()
            except:
                print('Could not open file!')
                print()
                print_menu()
                continue

            # Create output file
            if option == '1':
                try:
                    with open(output_filename, 'wb') as f:
                        f.write(aacs.encrypt(data))
                except:
                    print('Could not open file!')
                    print()
                    print_menu()
                    continue
            
            if option == '2':
                device_id: int = ask_decrypting_device()
                node_id: int = device_id_to_node_id(aacs.t, device_id)
                
                try:
                    data: bytes = aacs.decrypt(node_id, data)
                except KeyNotFound as e:
                    print(f"Key not found: {e}")
                    print()
                    print_menu()
                    continue
                except ValueError as e:
                    print(f"Value Error: {e}")
                    print()
                    print_menu()
                    continue
                
                try:
                    with open(output_filename, 'wb') as f:
                        f.write(data)
                except:
                    print('Could not open file!')
                    print()
                    print_menu()
                    continue

        print()
        print_menu()


if __name__ == "__main__":

    try:
        main()
    except KeyboardInterrupt:
        print('Exiting...')
        exit(0)
