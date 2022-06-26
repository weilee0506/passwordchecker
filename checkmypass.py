# 使用haveibeenpwned.com的api去測密碼有沒有被洩露

# 可以讓我們發送request
import requests
import hashlib
import sys

# api使用是用hash
# 也使用了k-anonymity k匿名性，只收密碼的hash值的前5碼(底下的cbfda)
# 這樣可以確保api不會知道密碼的完整hash
# url = "https://api.pwnedpasswords.com/range/" + "cbfda"
# res = requests.get(url)
#
# print(res)


def request_api_data(query_char):
    # 取得含有前5碼的所有hash
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    # print(res)
    # print(F"Error fetching: {res.status_code}, check the api and try again")

    if res.status_code != 200:
        error_mag = F"Error fetching: {res.status_code}, check the api and try again"
        # error後面如果直接寫f string會吃不到，所以先存成一個變數
        raise RuntimeError(error_mag)
    return res


def read_res(response):
    # 可以去讀response的值
    # api的response是取得前五碼一樣的後面剩下部分和被hacked的數量 (e.g.007F6D133ECAC7376F0868146879AC82118:4)
    print(response.text)


def get_password_leaks_count(hashes, hash_to_check):
    # 把api response得到的hashes和count分開
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        # 看我要測的hash_to_check在response裡面有沒有，有的話return count
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # 把password跟api response做對照

    # 在hash之前要先encode成utf-8的格式
    # print(password.encode("utf-8"))
    # hash object
    # print(hashlib.sha1(password.encode("utf-8")))
    # hash object轉乘hexadecimal string十六進位
    # print(hashlib.sha1(password.encode("utf-8")).hexdigest())
    # 變大寫，才能跟api response做對應
    # print(hashlib.sha1(password.encode("utf-8")).hexdigest().upper())

    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    # 把前5個跟後面存成變數
    first5_char, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5_char)
    # print(sha1_password)
    # print("----------")
    # print(first5_char)
    # print(tail)
    # print("----------")
    # print(response)
    return get_password_leaks_count(response, tail)


def main(args):
    # args接收要測的密碼
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times!! you should change it!!")
        else:
            print(f"{password} was not found!! Carry on!!")
    return "done!!"


# 這個file只有在他是main時才會執行
if __name__ == "__main__":
    # 要測幾個密碼都可以
    # sys.exit確保執行完會從這個file exit，回到command line，done!!會出現
    sys.exit(main(sys.argv[1:]))