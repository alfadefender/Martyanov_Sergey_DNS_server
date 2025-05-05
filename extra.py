from dataclasses import dataclass

@dataclass
class Request:
    q_name : str
    q_type : str
    q_class : str

@dataclass
class Response:
    r_name : str
    r_type : str
    r_class : str
    r_ttl : int
    r_last_length : int
    r_data : str | tuple

@dataclass
class CacheRecord(Response):
    r_added_at: int

types = {
    1 : "A",
    2 : "NS",
    28 : "AAAA",
    12 : "PTR"
}

types_ = {
    "A" : 1,
    "NS" : 2,
    "AAAA" : 28,
    "PTR" : 12
}

classes = {
    1 : "IN"
}

classes_ = {
    "IN" : 1
}

def parse_domain_name(array : bytes, pointer : int) -> [int, str]:
    name = ""
    link = pointer
    is_linked = False

    # собираем доменное имя
    while True:
        cur_byte1 = to_binary(array[link])
        cur_byte2 = to_binary(array[link + 1])

        if int(cur_byte1, 2) == 0:
            pointer += 1
            break

        if cur_byte1.startswith("00"):
            length = int(cur_byte1[2:], 2)
            link += 1
            if not is_linked:
                pointer += 1
                pointer += length

            name += array[link: link + length].decode() + "."
            link += length

        else:
            link = int((cur_byte1 + cur_byte2)[2:], 2)
            if not is_linked:
                pointer += 1
            is_linked = True

    return pointer, name

def encode_domain_name(domain_name : str):
    array = domain_name.split(".")
    result = []
    for part in array:
        if part:
            result += [len(part)]
            for letter in part:
                result += [ord(letter)]
    result += [0]

    return bytes(result)

def parse_nth_bytes(array : bytes, pointer : int, count : int, flag : bool = False) -> [int, int]:
    temp = []
    for i in range(count):
        temp += [to_binary(array[pointer + i])]

    if flag:
        return pointer + count, tuple(map(lambda x: int(x, 2), temp))

    return pointer + count, int("".join(temp), 2)

def to_binary(num):
    string = ""

    while num:
        string += str(num % 2)
        num //= 2

    return "0" * (8 - len(string)) + string[::-1]

def to_nth_bytes(num, n):
    string = ""

    while num:
        string += str(num % 2)
        num //= 2

    resulted_str = "0" * (8 * n - len(string)) + string[::-1]

    return [int(resulted_str[i * 8: i * 8 + 8], 2) for i in range(n)]
