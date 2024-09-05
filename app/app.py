from flask import Flask, request, Response
from flask_cors import CORS, cross_origin
import phishing
import json

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'


@app.post('/phishing')
@cross_origin()
def is_phishing():
    body = request.json
    domain = phishing.prepare_domain(body)
    if domain is None:
        return Response("no url provided", status=400)
    return Response(response=json.dumps(phishing.is_phishing(domain)), status=200, content_type='application/json')


if __name__ == '__main__':
    phishing.load_models()
    app.run(debug=True)
