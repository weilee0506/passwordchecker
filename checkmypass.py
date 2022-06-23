# 使用haveibeenpwned.com的api去測密碼有沒有被洩露

# 可以讓我們發送request
import requests
import hashlib

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
    print(res)
    # print(F"Error fetching: {res.status_code}, check the api and try again")

    if res.status_code != 200:
        error_mag = F"Error fetching: {res.status_code}, check the api and try again"
        # error後面如果直接寫f string會吃不到，所以先存成一個變數
        raise RuntimeError(error_mag)
    return res


def pwned_api_check(password):
    # 把password跟api reponse做對照

    # 在hash之前要先encode成utf-8的格式
    print(password.encode("utf-8"))
    # hash object
    print(hashlib.sha1(password.encode("utf-8")))
    # hash object轉乘hexadecimal string十六進位
    print(hashlib.sha1(password.encode("utf-8")).hexdigest())
    # 變大寫，才能跟api response做對應
    print(hashlib.sha1(password.encode("utf-8")).hexdigest().upper())

    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    # print(sha1_password)
    return sha1_password


request_api_data("cbfda")

pwned_api_check("zzz")