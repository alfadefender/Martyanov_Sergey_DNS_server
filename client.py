import socket
from extra import *


class Client:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _parse_response(self, response : bytes):
        requests = []
        answers = []
        authority_records = []
        additional_records = []

        array = response

        id_ = array[:2]
        # dns-заголовок
        QR = array[2] & 128
        OP_code = array[2] & 120
        authoritative = array[2] & 4
        truncated = array[2] & 2
        recursion_hz = array[2] & 1
        recursion_able = array[3] & 128
        z = array[3] & 112
        r_code = array[3] & 15

        qd_count = int(to_binary(array[4]) + to_binary(array[5]), 2)
        an_count = int(to_binary(array[6]) + to_binary(array[7]), 2)
        ns_count = int(to_binary(array[8]) + to_binary(array[9]), 2)
        ar_count = int(to_binary(array[10]) + to_binary(array[11]), 2)

        idx = 0
        pointer = 12
        while idx < qd_count:
            pointer, q_name = parse_domain_name(array, pointer)

            pointer, q_type = parse_nth_bytes(array, pointer, 2)

            pointer, q_class = parse_nth_bytes(array, pointer, 2)

            temp_type = types.get(q_type)
            result_type = temp_type if temp_type is not None else str(q_type)
            temp_class = classes.get(q_class)
            result_class = temp_class if temp_class is not None else str(
                q_class)

            requests += [Request(q_name, result_type, result_class)]
            idx += 1

        idx = 0
        while idx < an_count:
            pointer, name_ = parse_domain_name(array, pointer)

            pointer, type_ = parse_nth_bytes(array, pointer, 2)

            pointer, class_ = parse_nth_bytes(array, pointer, 2)

            pointer, ttl_ = parse_nth_bytes(array, pointer, 4)

            pointer, last_length_ = parse_nth_bytes(array, pointer, 2)

            temp = types.get(type_)
            match temp:
                case "A":
                    pointer, data_ = parse_nth_bytes(array, pointer, 4, True)

                case "AAAA":
                    pointer, data_ = parse_nth_bytes(array, pointer, 16, True)

                case "NS":
                    pointer, data_ = parse_domain_name(array, pointer)

                case "PTR":
                    pointer, data_ = parse_domain_name(array, pointer)

                case _:
                    data_ = None
                    pointer += last_length_

            temp_type = types.get(type_)
            result_type = temp_type if temp_type is not None else str(type_)
            temp_class = classes.get(class_)
            result_class = temp_class if temp_class is not None else str(
                class_)

            answers += [Response(
                name_,
                result_type,
                result_class,
                ttl_,
                last_length_,
                data_
            )]
            idx += 1

        idx = 0
        while idx < ns_count:
            pointer, name_ = parse_domain_name(array, pointer)

            pointer, type_ = parse_nth_bytes(array, pointer, 2)

            pointer, class_ = parse_nth_bytes(array, pointer, 2)

            pointer, ttl_ = parse_nth_bytes(array, pointer, 4)

            pointer, last_length_ = parse_nth_bytes(array, pointer, 2)

            temp = types.get(type_)
            match temp:
                case "A":
                    pointer, data_ = parse_nth_bytes(array, pointer, 4, True)

                case "AAAA":
                    pointer, data_ = parse_nth_bytes(array, pointer, 16, True)

                case "NS":
                    pointer, data_ = parse_domain_name(array, pointer)

                case "PTR":
                    pointer, data_ = parse_domain_name(array, pointer)

                case _:
                    data_ = None
                    pointer += last_length_

            temp_type = types.get(type_)
            result_type = temp_type if temp_type is not None else str(type_)
            temp_class = classes.get(class_)
            result_class = temp_class if temp_class is not None else str(
                class_)

            authority_records += [Response(
                name_,
                result_type,
                result_class,
                ttl_,
                last_length_,
                data_
            )]
            idx += 1

        idx = 0
        while idx < ar_count:
            pointer, name_ = parse_domain_name(array, pointer)

            pointer, type_ = parse_nth_bytes(array, pointer, 2)

            pointer, class_ = parse_nth_bytes(array, pointer, 2)

            pointer, ttl_ = parse_nth_bytes(array, pointer, 4)

            pointer, last_length_ = parse_nth_bytes(array, pointer, 2)

            temp = types.get(type_)
            match temp:
                case "A":
                    pointer, data_ = parse_nth_bytes(array, pointer, 4, True)

                case "AAAA":
                    pointer, data_ = parse_nth_bytes(array, pointer, 16, True)

                case "NS":
                    pointer, data_ = parse_domain_name(array, pointer)

                case "PTR":
                    pointer, data_ = parse_domain_name(array, pointer)

                case _:
                    data_ = None
                    pointer += last_length_

            temp_type = types.get(type_)
            result_type = temp_type if temp_type is not None else str(type_)
            temp_class = classes.get(class_)
            result_class = temp_class if temp_class is not None else str(class_)

            additional_records += [Response(
                name_,
                result_type,
                result_class,
                ttl_,
                last_length_,
                data_
            )]
            idx += 1

        print(f"id = {id_}")
        print(f"QR = {QR}")
        print(f"OP_code = {OP_code}")
        print(f"authoritative = {authoritative}")
        print(f"truncated = {truncated}")
        print(f"recursion_hz = {recursion_hz}")
        print(f"recursion_able = {recursion_able}")
        print(f"r_code = {r_code}")
        print(f"ns_count = {ns_count}")
        print(f"ar_count = {ar_count}")
        print("requests")
        print(requests)
        print("###################")
        print("answers")
        print(answers)
        print("###################")
        print("authority records")
        print(authority_records)
        print("###################")
        print("additional records")
        print(additional_records)

    def _create_request(self, domain_name : str):
        request = []
        type_ = [0, 1]

        id_ = [59, 13]
        flags = [1, 0]
        qd_count = [0, 1]
        an_count = [0, 0]
        ns_count = [0, 0]
        ar_count = [0, 0]
        request_data = [
            *encode_domain_name(domain_name),
            *type_,
            0, 1
        ]
        request += [*id_]
        request += [*flags]
        request += [*qd_count]
        request += [*an_count]
        request += [*ns_count]
        request += [*ar_count]
        request += [*request_data]

        return bytes(request)

    def run(self):
        request = self._create_request("vk.com")
        self.client_socket.sendto(request, ("127.0.0.1", 12345))
        try:
            data = self.client_socket.recv(512)
            if data:
                self._parse_response(data)
            else:
                print("No data")

        except Exception as e:
            print("Exception: ", e)

        self.client_socket.close()

if __name__ == "__main__":
    client = Client()
    client.run()
