import signal
import socket
import pickle
import threading
import time
from queue import Queue
from copy import deepcopy

from extra import *


running = True

def signal_handler(sig, frame):
    global running
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


class Cache:
    def __init__(self):
        self._type_A = {}
        self._type_AAAA = {}
        self._type_NS = {}
        self._type_PTR = {}
        self._filename = "config.pkl"
        self.lock = threading.Lock()

    def dump(self):
        with open(self._filename, "wb") as file:
            pickle.dump([self._type_A, self._type_AAAA, self._type_NS, self._type_PTR], file)

    def load(self):
        try:
            with open(self._filename, "rb") as file:
                self._type_A, self._type_AAAA, self._type_NS, self._type_PTR = pickle.load(file)

        except FileNotFoundError:
            print("INFO : Nothing to load")

    def _clean_dict(self, cur_time, cur_dict):
        copied_dict = deepcopy(cur_dict)
        for domain_name, list_record in copied_dict.items():
            for record in list_record:
                if record.r_ttl + record.r_added_at <= cur_time:
                    cur_dict[domain_name].remove(record)

    def _clean_up(self):
        while running:
            time.sleep(30)
            with self.lock:
                cur_time = int(time.time())
                self._clean_dict(cur_time, self._type_A)
                self._clean_dict(cur_time, self._type_AAAA)
                self._clean_dict(cur_time, self._type_NS)
                self._clean_dict(cur_time, self._type_PTR)

            self.dump()
            print("INFO : Cache is cleaned")

    def clean_up(self):
        threading.Thread(target=self._clean_up, daemon=True).start()

    def _add_record(self, domain_name : str, record : CacheRecord):
        match record.r_type:
            case "A":
                temp = self._type_A.get(domain_name)
                if temp is None:
                    self._type_A[domain_name] = [record]

                else:
                    self._type_A[domain_name] += [record]

            case "AAAA":
                temp = self._type_AAAA.get(domain_name)
                if temp is None:
                    self._type_AAAA[domain_name] = [record]

                else:
                    self._type_AAAA[domain_name] += [record]

            case "NS":
                temp = self._type_NS.get(domain_name)
                if temp is None:
                    self._type_NS[domain_name] = [record]

                else:
                    self._type_NS[domain_name] += [record]

            case "PTR":
                temp = self._type_PTR.get(domain_name)
                if temp is None:
                    self._type_PTR[domain_name] = [record]

                else:
                    self._type_PTR[domain_name] += [record]

    def add_records(self, list_records : list[tuple[str, CacheRecord]]):
        with self.lock:
            for domain_name, record in list_records:
                self._add_record(domain_name, record)

    def get_type_A(self, domain_name : str) -> None | list[CacheRecord]:
        temp = self._type_A.get(domain_name)
        if temp == []:
            temp = None

        return temp

    def get_type_AAAA(self, domain_name : str) -> None | list[CacheRecord]:
        temp = self._type_AAAA.get(domain_name)
        if temp == []:
            temp = None

        return temp

    def get_type_NS(self, domain_name : str) -> None | list[CacheRecord]:
        temp = self._type_NS.get(domain_name)
        if temp == []:
            temp = None

        return temp

    def get_type_PTR(self, domain_name : str) -> None | list[CacheRecord]:
        temp = self._type_PTR.get(domain_name)
        if temp == []:
            temp = None

        return temp

    def get_by_domain_name(self, domain_name, cur_type) -> None | list[CacheRecord]:
        match cur_type:
            case "A":
                return self.get_type_A(domain_name)

            case "AAAA":
                return self.get_type_AAAA(domain_name)

            case "NS":
                return self.get_type_NS(domain_name)

            case "PTR":
                return self.get_type_PTR(domain_name)
        return None


class Server:
    def __init__(self):
        self.cache = Cache()
        self.cache.load()
        self.cache.clean_up()
        self.host = "127.0.0.1"
        self.port = 12345
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ask_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.settimeout(2)
        self.ask_socket.settimeout(5)
        self.root_servers = [
            "198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13",
            "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
            "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
            "202.12.27.33"
        ]

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
            result_class = temp_class if temp_class is not None else str(
                class_)

            additional_records += [Response(
                name_,
                result_type,
                result_class,
                ttl_,
                last_length_,
                data_
            )]
            idx += 1

        headers = {
            "id" : id_,
            "flags" : {
                "qr" : QR,
                "op_code" : OP_code,
                "authoritative" : authoritative,
                "truncated" : truncated,
                "recursion_hz" : recursion_hz,
                "recursion_able" : recursion_able,
                "z" : z,
                "r_code" : r_code
            },
            "qd_count" : qd_count,
            "an_count" : an_count,
            "ns_count" : ns_count,
            "ar_count" : ar_count
        }

        return headers, requests, answers, authority_records, additional_records

    def _create_response(self, headers : dict, request : Request, data : list[Response]) -> bytes:
        response = []
        type_ = [0, types_[request.q_type]]

        id_ = headers["id"]
        # 1_0000_0_0_0 | 1_000_0000
        flags = [129, 128] # if flags[0] +2 -> truncated
        qd_count = [0, 1]
        an_count = [0, 0]
        ns_count = [0, 0]
        ar_count = [0, 0]
        request_data = [
            *encode_domain_name(request.q_name),
            *type_,
            0, 1
        ]

        answer_data = []
        idx = 0
        cur_weight = 12 + len(request_data)
        while idx < len(data):
            cur_domain_name = encode_domain_name(data[idx].r_name)
            cur_type = [0, types_[data[idx].r_type]]
            cur_ttl = to_nth_bytes(data[idx].r_ttl, 4)
            cur_data_name = data[idx].r_data
            cur_last_length = to_nth_bytes(len(cur_data_name), 2)

            if cur_weight + len(cur_domain_name) + len(cur_data_name) + 10 > 512:
                flags[0] += 2
                break

            answer_data += [
                *cur_domain_name,
                *cur_type,
                0, 1,
                *cur_ttl,
                *cur_last_length,
                *cur_data_name
            ]

            cur_weight += len(answer_data)

            idx += 1

        an_count[1] = idx

        response += [*id_]
        response += [*flags]
        response += [*qd_count]
        response += [*an_count]
        response += [*ns_count]
        response += [*ar_count]
        response += [*request_data]
        response += [*answer_data]

        return bytes(response)

    def _create_error_response(self, headers : dict, request : Request, code : int) -> bytes:
        response = []
        type_ = [0, types_[request.q_type]]

        id_ = headers["id"]
        # 1_0000_0_0_1 | 1_000_0000
        flags = [129, 128 + code] # if flags[0] +2 -> truncated
        qd_count = [0, 1]
        an_count = [0, 0]
        ns_count = [0, 0]
        ar_count = [0, 0]
        request_data = [
            *encode_domain_name(request.q_name),
            *type_,
            0, 1
        ]
        response += [*id_]
        response += [*flags]
        response += [*qd_count]
        response += [*an_count]
        response += [*ns_count]
        response += [*ar_count]
        response += [*request_data]

        return bytes(response)

    def _create_request(self, headers : dict, user_request : Request) -> bytes:
        request = []
        type_ = [0, types_[user_request.q_type]]

        id_ = headers["id"]
        # 0_0000_0_0_0 | 0_000_0000
        flags = [0, 0]
        qd_count = [0, 1]
        an_count = [0, 0]
        ns_count = [0, 0]
        ar_count = [0, 0]
        request_data = [
            *encode_domain_name(user_request.q_name),
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

    def load_info_to_cache(self, container : list[Response]):
        list_records = []
        for elem in container:
            domain_name = elem.r_name
            record = CacheRecord(
                elem.r_name,
                elem.r_type,
                elem.r_class,
                elem.r_ttl,
                elem.r_last_length,
                elem.r_data,
                int(time.time())
            )

            list_records += [(domain_name, record)]

        self.cache.add_records(list_records)

    def _ask_servers_recursive(self, headers : dict, user_request : Request) -> list[Response] | None:
        servers = [(self.root_servers[i], 53) for i in range(len(self.root_servers))]
        answer = None

        def wrapper(servers_to_send):
            nonlocal answer
            request = self._create_request(headers, user_request)
            for (server, port) in servers_to_send:
                if answer is not None:
                    break
                try:
                    self.ask_socket.sendto(request, (server, port))

                    try:
                        data, addr = self.ask_socket.recvfrom(512)
                    except TimeoutError:
                        data = None

                    if data:
                        cur_headers, requests, answers, auth_recs, add_recs = self._parse_response(data)

                        self.load_info_to_cache(answers)
                        self.load_info_to_cache(auth_recs)
                        self.load_info_to_cache(add_recs)

                        if len(answers) != 0:
                            answer = answers
                            break

                        else:
                            list_servers = []
                            for elem in add_recs:
                                if elem.r_type == "A":
                                    list_servers += [(".".join(list(map(str, elem.r_data))), 53)]

                            wrapper(list_servers)

                except Exception as e:
                    print(f"WARNING in <_ask_servers_recursive.wrapper> : {e}")

        wrapper(servers)

        return answer

    def _ask_servers_recursive_bfs(self, headers : dict, user_request : Request) -> list[Response] | None:
        que = Queue()
        for i in range(len(self.root_servers)):
            que.put((self.root_servers[i], 53))

        answer = None
        counter = 1000

        while not que.empty() and answer is None and counter > 0:
            counter -= 1
            request = self._create_request(headers, user_request)
            server, port = que.get()
            try:
                self.ask_socket.sendto(request, (server, port))

                try:
                    data, addr = self.ask_socket.recvfrom(512)
                except TimeoutError:
                    data = None

                if data:
                    cur_headers, requests, answers, auth_recs, add_recs = self._parse_response(data)

                    self.load_info_to_cache(answers)
                    self.load_info_to_cache(auth_recs)
                    self.load_info_to_cache(add_recs)

                    if len(answers) != 0:
                        answer = answers
                        break

                    else:
                        for elem in add_recs:
                            if elem.r_type == "A":
                                que.put((".".join(list(map(str, elem.r_data))), 53))

            except Exception as e:
                print(f"WARNING in <_ask_servers_recursive.wrapper> : {e}")

        return answer

    def run(self):
        self.server_socket.bind((self.host, self.port))
        print(f"Server starts at ({self.host}, {self.port})")

        try:
            while running:
                headers = None
                cur_request = None
                addr = None
                try:
                    try:
                        data, addr = self.server_socket.recvfrom(512)
                        print(f"Received data from {addr}")
                    except TimeoutError:
                        data = None

                    if data:
                        headers, requests, answers, authority_records, additional_records = self._parse_response(data)
                        print("Data parsed")

                        if not headers["flags"]["qr"]: # запрос
                            cur_request = requests[-1]
                            domain_name = cur_request.q_name
                            cur_type = cur_request.q_type
                            temp_find = self.cache.get_by_domain_name(domain_name, cur_type)
                            if temp_find is not None and temp_find != []:
                                response = self._create_response(headers, cur_request, temp_find)
                                self.server_socket.sendto(response, addr)
                                print(f"Sent response from cache to {addr}")

                            else:
                                all_answers = self._ask_servers_recursive_bfs(headers, cur_request)
                                if all_answers is None:
                                    all_answers = self._ask_servers_recursive(
                                        headers, cur_request)
                                response = self._create_response(headers,
                                                                 cur_request,
                                                                 all_answers)
                                self.server_socket.sendto(response, addr)
                                print(f"Sent response from servers to {addr}")

                except TypeError as e:
                    print(f"EXCEPTION in <Server.run> : {e}")
                    response = self._create_error_response(
                        headers,
                        cur_request,
                        3       # name not founded
                    )
                    print(f"Sending error package to {addr}")
                    self.server_socket.sendto(response, addr)

                except Exception as e:
                    print(f"EXCEPTION in <Server.run> : {e}")
                    print(type(e))
                    response = self._create_error_response(
                        headers,
                        cur_request,
                        2       # server_error
                    )
                    print(f"Sending error package to {addr}")
                    self.server_socket.sendto(response, addr)

        finally:
            self.cache.dump()
            self.server_socket.close()
            self.ask_socket.close()


if __name__ == "__main__":
    server = Server()
    server.run()
