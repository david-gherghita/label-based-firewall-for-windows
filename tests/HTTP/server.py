from flask import Flask, request, Response, render_template, send_file
from os import path


app = Flask(__name__)


@app.route('/test_head_1', methods=['HEAD'])
def test_head_1():
    response = Response()
    response.headers.set('test_header', 'test_header_value_098f6bcd4621d373cade4e832627b4f6')
    return response


@app.route('/test_head_2', methods=['HEAD'])
def test_head_2():
    f_path = path.abspath(path.join(path.dirname(__file__), 'files/test_head_2.txt'))
    f_lines = open(f_path).readlines()

    response = Response()
    response.set_cookie('test_cookie_1', f_lines[0].strip())
    response.set_cookie('test_cookie_2', f_lines[1].strip())
    response.set_cookie('test_cookie_3', f_lines[2].strip())
    return response


@app.route('/test_get_1', methods=['GET'])
def test_get_1():
    return render_template('test_get_1.html')


@app.route('/test_get_2', methods=['GET'])
def test_get_2():
    return render_template('test_get_2.html')


@app.route('/test_get_3', methods=['GET'])
def test_get_3():
    f_path = path.abspath(path.join(path.dirname(__file__), 'files/test_head_2.txt'))
    return send_file('files/file.dat', mimetype='application/octet-stream')


@app.route('/test_post', methods=['POST'])
def test_post():
    if 'file' not in request.files:
        return 'No file was included in the request', 400
    received_file = request.files['file']
    f_path = path.abspath(path.join(path.dirname(__file__), 'files/file.dat'))
    with open(f_path, 'rb') as stored_file:
        if received_file.read() == stored_file.read():
            return 'OK', 200
        else:
            return 'The received file is not the same as the stored file', 400


@app.route('/test_delete/<id>', methods=['DELETE'])
def test_delete(id):
    response = Response()
    if id == '948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d':
        response.set_data('b3eacd33433b31b5252351032c9b3e7a2e7aa7738d5decdf0dd6c62680853c06')
    return response


@app.route('/test_put/<id>', methods=['PUT'])
def test_put(id):
    response = Response()

    if 'file' not in request.files:
        return 'No file was included in the request', 400

    received_file = request.files['file']
    f_path = path.abspath(path.join(path.dirname(__file__), 'files/file.dat'))
    with open(f_path, 'rb') as stored_file:
        if received_file.read() != stored_file.read():
            return 'The received file is not the same as the stored file', 400

    if id == '8e13ffc9fd9d6a6761231a764bdf106b':
        response.set_data('e23f138bb95b057da97ba860fa23b1da')
        return response
    else:
        return "", 400


if __name__ == '__main__':
    app.run()
