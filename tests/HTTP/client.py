from os import path
import requests

SERVER = "http://169.254.26.45:5000/"

def test_head_1():
    r = requests.head(SERVER + 'test_head_1')
    header_value = r.headers.get('test_header')
    return header_value == 'test_header_value_098f6bcd4621d373cade4e832627b4f6'


def test_head_2():
    f_path = path.abspath(path.join(path.dirname(__file__), 'files/test_head_2.txt'))
    f_lines = open(f_path).readlines()

    r = requests.head(SERVER + 'test_head_2')
    cookies = r.cookies.get_dict()

    if ('test_cookie_1' in cookies and cookies['test_cookie_1'] == f_lines[0].strip() and
        'test_cookie_2' in cookies and cookies['test_cookie_2'] == f_lines[1].strip() and
        'test_cookie_3' in cookies and cookies['test_cookie_3'] == f_lines[2].strip()):
        return True
    return False


def test_get_1():
    f_path = path.abspath(path.join(path.dirname(__file__), 'templates/test_get_1.html'))
    body = open(f_path).read()

    r = requests.get(SERVER + 'test_get_1')
    return body == r.text


def test_get_2():
    f_path = path.abspath(path.join(path.dirname(__file__), 'templates/test_get_2.html'))
    body = open(f_path).read()

    r = requests.get(SERVER + 'test_get_2')
    return body == r.text


def test_get_3():
    r = requests.get(SERVER + 'test_get_3')
    received_file = r.content
    f_path = path.abspath(path.join(path.dirname(__file__), 'files/file.dat'))
    with open(f_path, 'rb') as stored_file:
        return received_file == stored_file.read()


def test_post():
    f_path = path.abspath(path.join(path.dirname(__file__), 'files/file.dat'))
    with open(f_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(SERVER + 'test_post', files=files)
    return response.status_code == 200


def test_delete():
    r  = requests.delete(SERVER + 'test_delete/'
        '948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d')
    return r.text == 'b3eacd33433b31b5252351032c9b3e7a2e7aa7738d5decdf0dd6c62680853c06'


def test_put():
    f_path = path.abspath(path.join(path.dirname(__file__), 'files/file.dat'))
    with open(f_path, 'rb') as file:
        files = {'file': file}
        r  = requests.put(SERVER + 'test_put/8e13ffc9fd9d6a6761231a764bdf106b', files=files)
        return r.text == 'e23f138bb95b057da97ba860fa23b1da'


TEST_FUNCTIONS = [test_head_1, test_head_2, test_get_1, test_get_2, test_get_3, test_post, test_delete, test_put]
TEST_NAMES = ['"HEAD" - 1', '"HEAD" - 2', '"GET" - 1', '"GET" - 2', '"GET" - 3', '"POST"', '"DELETE"', '"PUT"']


def main():
    for i in range(len(TEST_FUNCTIONS)):
        print(TEST_NAMES[i] + ' - ', end='')
        if TEST_FUNCTIONS[i]():
            print('PASSED')
        else:
            print('FAILED')


if __name__ == "__main__":
    main()
