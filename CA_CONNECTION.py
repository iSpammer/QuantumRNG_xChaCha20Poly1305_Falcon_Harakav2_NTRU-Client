# Import the requests module
import ast
import sys

import requests

# Define a class that handles the requests
class RequestHandler:

    # Define the constructor that takes the server address and port as arguments
    def __init__(self, server_address, server_port):
        # Store the server address and port as attributes
        self.server_address = server_address
        self.server_port = server_port

    # Define a method that sends a post request with some data
    def post_request(self, data):
        # Send a post request to the server with the data
        response = requests.post(f"http://{self.server_address}:{self.server_port}/", data=data)

        # Print the status code and the content of the response
        print(f"Status code: {response.status_code}")
        print(f"Content: {response.text}")

    # Define a method that sends a get request
    def get_request(self, server_pub):
        # Send a get request to the server
        response = requests.get(f"http://{self.server_address}:{self.server_port}/chain_details_get?hashid={server_pub}")

        # Print the status code and the content of the response
        print(f"Status code: {response.status_code}")
        if response.status_code != 200:
            print("COMMUNICATION FAILED!")
            return False
        print(f"Content: {response.text}")
        # Import the json module
        import json

        # Define the output as a string
        resp = response.text.strip("\\")
        print("asd! ",resp)
        # Parse the output as a JSON object
        output = json.loads(response.text)

        # Get the chain and the length from the output
        chain = output["chain"]
        length = output["len"]

        # Print the chain length
        print(f"The chain length is {length}")
        # if(length > 1)
        #     return True;
        # Loop through the chain
        for block in chain:
            # Parse the block as a JSON object
            block = json.loads(block)

            # Get the block details
            block_number = block["block_number"]
            transactions = block["transactions"]
            previous_hash = block["previous_hash"]
            nonce = block["nonce"]
            hashid = block["hashid"]
            timestamp = block["timestamp"]

            pub_key_s_h = transactions["pub_key_s_h"]

            # Print the block details
            print(f"Block number: {block_number}")
            print(f"Transactions: {transactions}")
            print(f"Previous hash: {previous_hash}")
            print(f"Nonce: {nonce}")
            print(f"Hashid: {hashid}")
            print(f"Timestamp: {timestamp}")
            print(f"Public Key {pub_key_s_h}")
            print(f"Public Key type {type(pub_key_s_h)}")
            print(f"server Key {type(server_pub)}")

            print()
            if server_pub == pub_key_s_h:
                return True
            else:
                print('UNVERIFIABLE HASH TERMINATING NOW')
                sys.exit()
                return False

    # Define a method that does both the post and the get requests
    def do_both(self, data):
        # Call the post request method with the data
        # self.post_request(data)

        # Call the get request method
        self.get_request()

# Create an instance of the RequestHandler class with the server address and port
request_handler = RequestHandler("192.168.0.18", 5000)

# Define the data to send
data = {"var1": "foo", "var2": "bar", "var3": "baz"}

# Call the do_both method with the data
# print(request_handler.get_request(ast.literal_eval("[9513, 8537, 932, 4492, 2761, 11599, 10238, 5271, 1619, 64, 1122, 11931, 2474, 10832, 9653, 10723, 2991, 2071, 10133, 6203, 814, 6893, 12258, 10357, 6798, 3856, 9597, 5809, 7453, 3553, 12020, 99]")))
