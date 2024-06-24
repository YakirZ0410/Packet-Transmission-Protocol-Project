class Packet:
    def __init__(self, source_address, destination_address, sequence_number,
                 is_ack=False, data=None):
        self.__source_address = source_address
        self.__destination_address = destination_address
        self.__sequence_number = sequence_number
        self.__is_ack = is_ack
        self.__data = data

    def __repr__(self):
        # Return a string representation of the packet
        return f"Packet(Source IP: {self.get_source_address()}, Dest IP: {self.get_destination_address()}, #Seq: {self.get_sequence_number()}, Is ACK: {self.get_is_ack()}, Data: {self.get_data()})"

    def get_source_address(self):
        # Get the source address of the packet
        return self.__source_address

    def get_destination_address(self):
        # Get the destination address of the packet
        return self.__destination_address

    def get_sequence_number(self):
        # Get the sequence number of the packet
        return self.__sequence_number

    def set_sequence_number(self, seq_num):
        # Set the sequence number of the packet
        self.__sequence_number = seq_num

    def get_is_ack(self):
        # Check if the packet is an acknowledgment
        return self.__is_ack

    def get_data(self):
        # Get the data carried by the packet
        return self.__data if self.__data is not None else ""  # Return empty string if data is None


class Communicator:
    def __init__(self, address):
        # Initialize communicator attributes
        self.__address = address
        self.__num_seq_current = None

    def get_address(self):
        # Get the address of the communicator
        return self.__address

    def get_current_sequence_number(self):
        # Get the current sequence number of the communicator
        return self.__num_seq_current

    def set_current_sequence_number(self, seq_num):
        self.__num_seq_current = seq_num

    # Method to send a packet
    def send_packet(self, packet):
        # Set the current sequence number of the communicator
        print(f"Sender: Packet Seq Num: {self.get_current_sequence_number()} was sent")
        return packet

    # Method to increment the current sequence number
    def increment_current_seq_num(self):
        current_number = self.get_current_sequence_number()
        if current_number is None:
            self.set_current_sequence_number(0)
        else:
            counter = current_number + 1
            self.set_current_sequence_number(counter)

class Sender(Communicator):
    def __init__(self, address, num_letters_in_packet):
        super().__init__(address)
        self.__num_letters_in_packet = num_letters_in_packet


    def prepare_packets(self, message, destination_address):
        # Check if the message is empty
        if message == "":
            print("Not sending an empty string")
            return None

        # Check if the message contains only special characters
        if all(char in "!@#$%^&*()_+{}[];:'\"<>,.?/\\|`~-=" for char in message):
            print("Message contains only special characters")
            return []

        # Calculate the length of the message
        message_length = len(message)
        # Calculate the number of packets needed
        # Each packet can contain up to __num_letters_in_packet characters
        num_packets = (message_length + self.__num_letters_in_packet - 1) // self.__num_letters_in_packet
        packets = []

        for i in range(num_packets):
            # Determine the start and end index of characters for the current packet
            start_index = i * self.__num_letters_in_packet
            end_index = min((i + 1) * self.__num_letters_in_packet, message_length)
            packet_data = message[start_index:end_index]

            # Pad the packet data if needed to ensure each packet has the same length
            if len(packet_data) < self.__num_letters_in_packet:
                packet_data += ' ' * (self.__num_letters_in_packet - len(packet_data))

            # Create a Packet object with the appropriate data
            packet = Packet(self.get_address(), destination_address, i, data=packet_data)
            packets.append(packet)

        return packets

    # Method to receive acknowledgment
    def receive_ack(self, acknowledgment_packet):
        return acknowledgment_packet.get_is_ack()

class Receiver(Communicator):
    def __init__(self, address):
        super().__init__(address)
        self.__packets_received = []

    # Method to receive a packet
    def receive_packet(self, packet):
        # Append the received packet to the list of received packets
        self.__packets_received.append(packet)
        # Create an acknowledgment packet to send back to the sender
        acknowledgment_packet = Packet(packet.get_destination_address(), packet.get_source_address(),
                                       packet.get_sequence_number(), is_ack=True)
        print(f"Receiver: Received packet seq num: {packet.get_sequence_number()}")
        return acknowledgment_packet

    # Method to reconstruct message from received packets
    def get_message_by_received_packets(self):
        # Combine the data from received packets to reconstruct the original message
        message_parts = []

        for packet in self.__packets_received:
            message_parts.append(packet.get_data())

        original_message = ''.join(message_parts)

        return original_message

if __name__ == '__main__':
    source_address = "192.168.1.1"
    destination_address = "192.168.2.2"
    message = "What is up?"
    num_letters_in_packet = 3

    sender = Sender(source_address, num_letters_in_packet)
    receiver = Receiver(destination_address)
    # The sender prepares the packets for sending
    packets = sender.prepare_packets(message, receiver.get_address())

    # If packets is empty, it means the message contains only special characters
    if not packets:
        exit()
    # setting current packet
    start_interval_index = packets[0].get_sequence_number()
    # setting current packet in the sender and receiver
    sender.set_current_sequence_number(start_interval_index)
    receiver.set_current_sequence_number(start_interval_index)
    # setting the last packet
    last_packet_sequence_num = packets[-1].get_sequence_number()
    receiver_current_packet = receiver.get_current_sequence_number()

    while receiver_current_packet <= last_packet_sequence_num:
        current_index = sender.get_current_sequence_number()
        packet = packets[current_index]
        packet = sender.send_packet(packet)

        ack = receiver.receive_packet(packet)

        result = sender.receive_ack(ack)

        if result == True:
            sender.increment_current_seq_num()
            receiver.increment_current_seq_num()

        receiver_current_packet = receiver.get_current_sequence_number()

    full_message = receiver.get_message_by_received_packets()
    print(f"Receiver message: {full_message}")
