from project import create_app
import os
from flask import session

app = create_app()

@app.before_first_request
def set_user_type():
    session['user_type'] = None

if __name__ == '__main__':
    if 'DYNO' in os.environ:
        # Running on Heroku, use gunicorn
        port = int(os.environ.get('PORT'))
        app.run(host='0.0.0.0', port=port)
    else:
        # Running locally
        app.run(host='localhost', port=2000, debug=True)